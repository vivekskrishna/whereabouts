package openwisp

import (
	"context"
	"fmt"
	"net"
	"time"
	"net/http"
//	"net/url"
	"os"
        "io/ioutil"
	"strings"

	//"github.com/dougbtv/whereabouts/pkg/allocate"
	"github.com/dougbtv/whereabouts/pkg/logging"
	"github.com/dougbtv/whereabouts/pkg/types"
	"github.com/dougbtv/whereabouts/pkg/podData"
	"encoding/json"
)

var (
	// RequestTimeout defines how long the context timesout in
	RequestTimeout = 5 * time.Second

	// DatastoreRetries defines how many retries are attempted when updating the Pool
	DatastoreRetries = 20
)

var ipamConf types.IPAMConfig

type IPAMPlug struct {
        Type       string        `json:"ipamtype,omitempty"`
        Url        string        `json:"ipamurl,omitempty"`
	AppID      string        `json:"appid,omitempty"`
        Username   string        `json:"ipamuser,omitempty"`
        Password   string        `json:"ipampwd,omitempty"`
}

//decoding responses from openwisp api's
// get the token after authentication
type IPAMToken struct {
	Token      string        `json:"token"`
}

type SubnetDescription struct {
	Defaultgw   string       `json:"gw"`
}

//get the list of subnets to make sure the requested one is present and also extract default GW from description field
type SubnetInfo struct {
	Id      string        `json:"id"`
	Name	string        `json:"description"`
	Subnet  string        `json:"subnet"`
	Mask    string        `json:"mask"`
	Gateway string        `json:"gateway",omitempty`
}

type SubnetList struct {
	SList    []SubnetInfo    `json:"data"`
}

//json format to get IP details in a subnet
type SubnetIP struct {
	IP        string         `json:"ip_address",omitempty`
	Desc      string         `json:"description",omitempty`
	Hostname  string         `json:"hostname",omitempty`
	Gateway   string         `json:"is_gateway",omitempty`
	SubnetID  string         `json:"subnetId",omitempty`
	Id        string         `json:"id",omitempty`
}

//json format to reserve a new IP in a subnet
type SubnetIPCreate struct {
        IP        string         `json:"data",omitempty`
        Id        string         `json:"id",omitempty`
}

//array of SubnetIP presented as a list for a subnet ip addresses details
type SubnetIPList struct {
	SList     []SubnetIP     `json:"data",omitempty`
}

// IPPool is the interface that represents an manageable pool of allocated IPs
type IPPool interface {
	Allocations() []types.IPReservation
	Update(ctx context.Context, reservations []types.IPReservation) error
}

// Store is the interface that wraps the basic IP Allocation methods on the underlying storage backend
type Store interface {
	GetIPPool(ctx context.Context, ipRange string) (IPPool, error)
	Status(ctx context.Context) error
	Close() error
}

func getCredentials(ipam IPAMPlug) (string, error) {
    urlstring := "http://" + ipam.Url + "/api/v1/user/token/"
    client := &http.Client{
	Timeout: time.Second * 5,
    }

    req, err := http.NewRequest("GET", urlstring, nil)
    if err != nil {
	return "Error", fmt.Errorf("Got error %s", err.Error())
    }
    username := "root"
    password := "ragavendra"
    req.SetBasicAuth(username, password)
    resp, err := client.Do(req)
    if err != nil {
	return "Error", fmt.Errorf("Got error %s", err.Error())
    }  
    defer resp.Body.Close()
    if resp.StatusCode == 200 {
        body, _ := ioutil.ReadAll(resp.Body)
	var tok IPAMToken
        if err := json.Unmarshal(body, &tok); err != nil {
		return "", err
	}
        return tok.Token, err
    } 
    logging.Errorf("Response code is %s", resp.StatusCode)
    return "", err
}

func getGateway(token string, ipam IPAMPlug, subnetID string) string {

	urlstring := "http://" + ipam.Url + "/api/" + ipam.AppID + "/subnets/" + subnetID + "/addresses"
        client := &http.Client{}
        req, _ := http.NewRequest("GET", urlstring, nil)
        req.Header.Set("token", token)
        resp, _ := client.Do(req)
        defer resp.Body.Close()
        var ipList SubnetIPList
        if resp.StatusCode == 200 {
                body, _ := ioutil.ReadAll(resp.Body)
                if err := json.Unmarshal(body, &ipList); err != nil {
                        logging.Errorf("json decoding failure of %s with error %s",body,err)
                        return ""
                }
                logging.Debugf("decoded data is %v",ipList)
		for _,ips := range  ipList.SList {
                        if ips.Gateway == "1" {
				return ips.IP
                        }
                }
		return ""
	}
	return ""

}

func allocateIP(token string, ipam IPAMPlug, pod string , pool string) (net.IPNet, string, error) {
	var newip net.IPNet
	// First we will get the list of subnet to make sure we have the subnet of interest and also get teh Defalt GW for that subnet ID
        urlstring := "http://" + ipam.Url + "/api/" + ipam.AppID + "/subnets/"
	client := &http.Client{}
        req, _ := http.NewRequest("GET", urlstring, nil)
	req.Header.Set("token", token)
        resp, _ := client.Do(req)
	defer resp.Body.Close()
	var subnetList SubnetList
	if resp.StatusCode == 200 {
        	body, err := ioutil.ReadAll(resp.Body)
        	//logging.Debugf("Body is %s and %d",body,resp.StatusCode)
        	//var tok IPAMToken
        	if err := json.Unmarshal(body, &subnetList); err != nil {
			logging.Errorf("json decoding failure of %s with error %s",body,err)
                	return newip,"", err
        	}
		logging.Debugf("decoded data is %v",subnetList.SList)
		// we will go through the list to find the subnet of interest and extract its id and gw info
		
		id := ""
		gw := ""
		sn := ""
		mask := ""
		for _,subnets := range  subnetList.SList {
			if subnets.Name == pool {
				id = subnets.Id
				gw = getGateway(token, ipam, id)
				sn = subnets.Subnet
				mask = subnets.Mask
				break
			}
		}
		logging.Debugf("id for pool %s is %s with def gw %s and subnet %s/%s",pool,id,gw,sn,mask)


		// check if a entry already exists for the podRef
		urlstring := "http://" + ipam.Url + "/api/" + ipam.AppID + "/subnets/" + id + "/addresses"
                client := &http.Client{}
                req, _ := http.NewRequest("GET", urlstring, nil)
		req.Header.Set("token", token)
                resp, _ := client.Do(req)
                defer resp.Body.Close()
                var ipList SubnetIPList
                if resp.StatusCode != 200 {
                        return newip, "",fmt.Errorf("error")
                }
                body, _ = ioutil.ReadAll(resp.Body)
                if err := json.Unmarshal(body, &ipList); err != nil {
                        logging.Errorf("json decoding failure of %s with error %s",body,err)
                        return newip,"", err
                }
                logging.Debugf("response is %v",ipList.SList)
                ipId := ""
		ipAddr := ""
                for _, ipBlock := range ipList.SList {
                        if ipBlock.Hostname == pod {
                                ipId = ipBlock.Id
				ipAddr = ipBlock.IP
                                break
                        }
                }
                if ipId != "" {
                        logging.Debugf(" IP %s already allocated for pod %s",ipAddr, pod)
                        ipNet := ipAddr + "/" + sn
                        _,newip1,_ := net.ParseCIDR(ipNet)
                        newip.IP = net.ParseIP(ipAddr)
                        newip.Mask = newip1.Mask

                        return newip, gw ,nil 
                }
		//end of check

		// get the next free ip in subnet
		allocated := 0
		retries := DatastoreRetries
		for allocated < 1 &&  retries > 0 {
               		urlstring := "http://" + ipam.Url + "/api/" + ipam.AppID + "/subnets/addresses/first_free/" + id
        		client := &http.Client{}
			var subnetIP SubnetIP
                        subnetIP.Hostname = pod
                        ipDet_json,_ := json.Marshal(subnetIP)
                        req_body := strings.NewReader(string(ipDet_json))
        		req, _ := http.NewRequest("GET", urlstring, req_body)
			req.Header.Set("token", token)
			resp, _ := client.Do(req)
			defer resp.Body.Close()
                        if resp.StatusCode != 201 {
				logging.Debugf("Got response %s and %s",resp,err)
                                return newip, "", fmt.Errorf("error response %d",resp.StatusCode)
                        } else {
			    allocated = 1
			    retries--
			}
                        var IPDetails SubnetIPCreate 
			if err := json.Unmarshal(body, &IPDetails); err != nil {
                            logging.Errorf("json decoding failure of %s with error %s",body,err)
                            return newip,"", err
                        }
			ip := IPDetails.IP
			ipNet := ip + "/" + sn
		        _,newip1,_ := net.ParseCIDR(ipNet) 
                        newip.IP = net.ParseIP(ip)
			newip.Mask = newip1.Mask
			logging.Debugf("Allocation of IP %s for pod %s successfull",ip,pod)
			return newip, gw, nil
		}
        	return newip,gw, err
        }
        return newip, "",fmt.Errorf("error")
}

func deallocateIP(token string, ipam IPAMPlug, pod string , pool string) (net.IPNet, string, error) {
	var newip net.IPNet
        // First we will get the list of subnet to make sure we have the subnet of interest and also get teh Defalt GW for that subnet ID
        urlstring := "http://" + ipam.Url + "/api/" + ipam.AppID + "/subnets/"
        client := &http.Client{}
        req, _ := http.NewRequest("GET", urlstring, nil)
        req.Header.Set("token", token)
        resp, _ := client.Do(req)
        defer resp.Body.Close()
        var subnetList SubnetList
        if resp.StatusCode == 200 {
                body, _ := ioutil.ReadAll(resp.Body)
                //logging.Debugf("Body is %s and %d",body,resp.StatusCode)
                //var tok IPAMToken
                if err := json.Unmarshal(body, &subnetList); err != nil {
                        logging.Errorf("json decoding failure of %s with error %s",body,err)
                        return newip,"", err
                }
                logging.Debugf("decoded data is %v",subnetList.SList)
                // we will go through the list to find the subnet of interest and extract its id and gw info

                id := ""
                gw := ""
                sn := ""
                mask := ""
                for _,subnets := range  subnetList.SList {
                        if subnets.Name == pool {
                                id = subnets.Id
                                gw = getGateway(token, ipam, id)
                                sn = subnets.Subnet
                                mask = subnets.Mask
                                break
                        }
                }
                logging.Debugf("id for pool %s is %s with def gw %s and subnet %s/%s",pool,id,gw,sn,mask)
		// get the next free ip in subnet
		// check if a entry already exists for the podRef
                urlstring := "http://" + ipam.Url + "/api/" + ipam.AppID + "/subnets/" + id + "/addresses"
                client := &http.Client{}
                req, _ := http.NewRequest("GET", urlstring, nil)
                req.Header.Set("token", token)
                resp, _ := client.Do(req)
                defer resp.Body.Close()
                var ipList SubnetIPList
                if resp.StatusCode != 200 {
                        return newip, "",fmt.Errorf("error")
                }
                body, _ = ioutil.ReadAll(resp.Body)
                if err := json.Unmarshal(body, &ipList); err != nil {
                        logging.Errorf("json decoding failure of %s with error %s",body,err)
                        return newip,"", err
                }
                logging.Debugf("response is %v",ipList.SList)
                ipId := ""
                ipAddr := ""
                for _, ipBlock := range ipList.SList {
                        if ipBlock.Hostname == pod {
                                ipId = ipBlock.Id
                                ipAddr = ipBlock.IP
                                break
                        }
                }

		if ipId == "" {
			logging.Errorf("No IP allocated for pod %s",pod)
			return newip,"", fmt.Errorf("error")
		}

		logging.Debugf("Trying to deallocate IP with id %s",ipId)
		urlstring = "http://" + ipam.Url + "/api/" + ipam.AppID + "/addresses/" + ipAddr + "/" + id 
		client1 := &http.Client{}
                req, _ = http.NewRequest("DELETE", urlstring, nil)
		req.Header.Set("token", token)
		resp1, _ := client1.Do(req)
		defer resp1.Body.Close()
                if resp1.StatusCode != 200 {
			logging.Errorf("Deallocating ip with id %s failed request is %s and response is %s",ipId,req,resp1)
                        return newip, "",fmt.Errorf("error")
                }
		logging.Debugf("Successfully deallocated IP for id %s",ipId)
		return newip, "success", nil
        }
        return newip, "",fmt.Errorf("error")
}


// IPManagement manages ip allocation and deallocation from a storage perspective
func IPManagement(mode int, ipamConf types.IPAMConfig, containerID string, podRef string) (net.IPNet, string, error) {

	logging.Debugf("IPManagement -- mode: %v / host: %v / containerID: %v / podRef: %v", mode, ipamConf.EtcdHost, containerID, podRef)

	var newip net.IPNet
	ipamProv := IPAMPlug{}
	// Skip invalid modes
	/*
	switch mode {
	case types.Allocate, types.Deallocate:
	default:
		return newip, fmt.Errorf("Got an unknown mode passed to IPManagement: %v", mode)
	}
	*/
	/*

// IPManagement manages ip allocation and deallocation from a storage perspective
func IPManagement(mode int, ipamConf types.IPAMConfig, containerID string, podRef string) (net.IPNet, string, error) {

	logging.Debugf("IPManagement -- mode: %v / host: %v / containerID: %v / podRef: %v", mode, ipamConf.EtcdHost, containerID, podRef)

	var newip net.IPNet
	ipamProv := IPAMPlug{}
	// Skip invalid modes
	/*
	switch mode {
	case types.Allocate, types.Deallocate:
	default:
		return newip, fmt.Errorf("Got an unknown mode passed to IPManagement: %v", mode)
	}
	*/
	/*
	var ipam Store
	var pool IPPool
	var err error
	switch ipamConf.Datastore {
	case types.DatastoreETCD:
		ipam, err = NewETCDIPAM(ipamConf)
	case types.DatastoreKubernetes:
		ipam, err = NewKubernetesIPAM(containerID, ipamConf)
	}
	if err != nil {
		logging.Errorf("IPAM %s client initialization error: %v", ipamConf.Datastore, err)
		return newip, fmt.Errorf("IPAM %s client initialization error: %v", ipamConf.Datastore, err)
	}
	defer ipam.Close()

	ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
	defer cancel()
        
	// Check our connectivity first
	if err := ipam.Status(ctx); err != nil {
		logging.Errorf("IPAM connectivity error: %v", err)
		return newip, err
	}
	*/

        jsonFile, err := os.Open("/etc/cni/net.d/whereabouts.d/whereabouts-ipam.conf")

        if err != nil {
            logging.Debugf("1")	
            return newip, "",fmt.Errorf("Error opening flat configuration file %s", err)
        }

        defer jsonFile.Close()

        jsonBytes, err := ioutil.ReadAll(jsonFile)
        if err != nil {
            logging.Debugf("2")
            return newip, "",fmt.Errorf("LoadIPAMConfig Flatfile - ioutil.ReadAll error: %s", err)
        }

        if err := json.Unmarshal(jsonBytes, &ipamProv); err != nil {
            logging.Debugf("3")
            return newip, "",fmt.Errorf("LoadIPAMConfig Flatfile - JSON Parsing Error: %s / bytes: %s", err, jsonBytes)
        } 

	logging.Debugf("IpamProv is %s and decoded is %v",jsonBytes, ipamProv)
	credential, err := getCredentials(ipamProv)
        logging.Debugf("The credential token is %s",credential)
	podRef = podData.GetPodAnnotation(ipamConf, podRef)
	logging.Debugf("podref after annotation search is %s",podRef)
	switch mode {
	case types.Allocate:
            return allocateIP(credential, ipamProv, podRef, "test")            	
	case types.Deallocate:
            return deallocateIP(credential, ipamProv, podRef, "test")
	default:
	    logging.Errorf("Unknown mode of operation")
	}
	return newip, "dummy", err
}

/*func main() {
	ipamConf.Kubernetes.KubeConfigPath = "/etc/cni/net.d/whereabouts.d/whereabouts.kubeconfig"
	fmt.Println("Hello, playground")
	//ip1,gw, _ := IPManagement(0,ipamConf,"dummy","default/test-5d68d4fdf6-pdmbr")
	//logging.Debugf("At main after allocate is %s with gw %s",string(ip1.IP),gw)
        IPManagement(1,ipamConf,"dummy","default/test-5d68d4fdf6-pdmbr")
}*/

