package openwisp

import (
	"context"
	"fmt"
	"net"
	"time"
	"net/http"
	"net/url"
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
	Name	string        `json:"name"`
	Subnet  string        `json:"subnet"`
	Desc    string        `json:"description"`
	IP      string        `json:"ip_address",omitempty`
}

type SubnetList struct {
	SList    []SubnetInfo    `json:"results"`
}

//json format to reserve a new IP in a subnet
type SubnetIPCreate struct {
	IP        string         `json:"ip_address"`
	Desc      string         `json:"description"`
	SubnetID  string         `json:"subnet"`
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
    resp, err := http.PostForm(urlstring,
	url.Values{"username": {ipam.Username}, "password": {ipam.Password}})
    defer resp.Body.Close()
    if resp.StatusCode == 200 {
        body, _ := ioutil.ReadAll(resp.Body)
        //logging.Debugf("Body is %s and %d",body,resp.StatusCode)
	var tok IPAMToken
        if err := json.Unmarshal(body, &tok); err != nil {
		return "", err
	}
        return tok.Token, err
    } 
    logging.Errorf("Response code is %s", resp.StatusCode)
    return "", err
}

func allocateIP(token string, ipam IPAMPlug, pod string , pool string) (net.IPNet, string, error) {
	var newip net.IPNet
	// First we will get the list of subnet to make sure we have the subnet of interest and also get teh Defalt GW for that subnet ID
        urlstring := "http://" + ipam.Url + "/api/v1/subnet/"
	client := &http.Client{}
        req, _ := http.NewRequest("GET", urlstring, nil)
	btoken := "Bearer " + token
	req.Header.Set("Authorization", btoken)
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
		for _,subnets := range  subnetList.SList {
			if subnets.Name == pool {
				id = subnets.Id
				var sgw SubnetDescription
				json.Unmarshal([]byte(subnets.Desc),&sgw)
				gw = sgw.Defaultgw
				sn = subnets.Subnet
				break
			}
		}
		logging.Debugf("id for pool %s is %s with def gw %s and subnet %s",pool,id,gw,sn)

		// check if a entry already exists for th podRef
		urlstring := "http://" + ipam.Url + "/api/v1/subnet/" + id + "/ip-address"
                client := &http.Client{}
                req, _ := http.NewRequest("GET", urlstring, nil)
                btoken := "Bearer " + token
                req.Header.Set("Authorization", btoken)
                resp, _ := client.Do(req)
                defer resp.Body.Close()
                var ipList SubnetList
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
                        if ipBlock.Desc == pod {
                                ipId = ipBlock.Id
				ipAddr = ipBlock.IP
                                break
                        }
                }
                if ipId != "" {
                        logging.Debugf(" IP %s already allocated for pod %s",ipAddr, pod)
			subnet_det := strings.Split(sn, "/")
                        ipNet := ipAddr + "/" + subnet_det[1]
                //      newip.IP = []byte(ip)
                //      newip.Mask = []byte(subnet_det[1])
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
               		urlstring := "http://" + ipam.Url + "/api/v1/subnet/" + id + "/get-next-available-ip/"
        		client := &http.Client{}
        		req, _ := http.NewRequest("GET", urlstring, nil)
        		btoken := "Bearer " + token
        		req.Header.Set("Authorization", btoken)
			resp, _ := client.Do(req)
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return newip, "", fmt.Errorf("error response %d",resp.StatusCode)
			}
			body, _ := ioutil.ReadAll(resp.Body)
			ip := strings.Trim(string(body), "\"")
			logging.Debugf("Next free IP available in pool %s is %s",pool, ip)
			var ipDet SubnetIPCreate
			ipDet.IP = ip
			ipDet.Desc = pod
			ipDet.SubnetID = id
			ipDet_json,_ := json.Marshal(ipDet)
			req_body := strings.NewReader(string(ipDet_json))
			logging.Debugf("encoded data is %s",ipDet_json)
			urlstring = "http://" + ipam.Url + "/api/v1/subnet/" + id + "/ip-address/"
			client1 := &http.Client{}
                        req, _ = http.NewRequest("POST", urlstring, req_body)
                        btoken = "Bearer " + token
                        req.Header.Set("Authorization", btoken)
			req.Header.Set("Content-Type", "application/json")
			logging.Debugf("Request is %s",req)
                        resp, err = client1.Do(req)
			defer resp.Body.Close()
                        if resp.StatusCode != 201 {
				logging.Debugf("Got response %s and %s",resp,err)
                                return newip, "", fmt.Errorf("error response %d",resp.StatusCode)
                        } else {
			    allocated = 1
			    retries--
			}
			subnet_det := strings.Split(sn, "/")
			ipNet := ip + "/" + subnet_det[1]
		//	newip.IP = []byte(ip)
		//	newip.Mask = []byte(subnet_det[1])
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
        urlstring := "http://" + ipam.Url + "/api/v1/subnet/"
	client := &http.Client{}
        req, _ := http.NewRequest("GET", urlstring, nil)
	btoken := "Bearer " + token
	req.Header.Set("Authorization", btoken)
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
		for _,subnets := range  subnetList.SList {
			if subnets.Name == pool {
				id = subnets.Id
				var sgw SubnetDescription
				json.Unmarshal([]byte(subnets.Desc),&sgw)
				gw = sgw.Defaultgw
				sn = subnets.Subnet
				break
			}
		}
		logging.Debugf("id for pool %s is %s with def gw %s and subnet %s",pool,id,gw,sn)
		// get the next free ip in subnet
		urlstring := "http://" + ipam.Url + "/api/v1/subnet/" + id + "/ip-address"
        	client := &http.Client{}
        	req, _ := http.NewRequest("GET", urlstring, nil)
        	btoken := "Bearer " + token
        	req.Header.Set("Authorization", btoken)
        	resp, _ := client.Do(req)
		defer resp.Body.Close()
        	var ipList SubnetList
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
		for _, ipBlock := range ipList.SList {
			if ipBlock.Desc == pod {
				ipId = ipBlock.Id
				break
			}
		}
		if ipId == "" {
			logging.Errorf("No IP allocated for pod %s",pod)
			return newip,"", fmt.Errorf("error")
		}
		logging.Debugf("Trying to deallocate IP with id %s",ipId)
		urlstring = "http://" + ipam.Url + "/api/v1/ip-address/" + ipId + "/" 
		client1 := &http.Client{}
                req, _ = http.NewRequest("DELETE", urlstring, nil)
                btoken = "Bearer " + token
                req.Header.Set("Authorization", btoken)
		resp1, _ := client1.Do(req)
		defer resp1.Body.Close()
                if resp1.StatusCode != 204 {
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

	logging.Debugf("IPManagement for openwisp -- mode: %v / host: %v / containerID: %v / podRef: %v", mode, ipamConf.EtcdHost, containerID, podRef)

	var newip net.IPNet
	ipamProv := IPAMPlug{}

        jsonFile, err := os.Open("/etc/cni/net.d/whereabouts.d/whereabouts-ipam.conf")

        if err != nil {
            logging.Debugf("1")	
            return newip, "",fmt.Errorf("Error opening flat configuration file %s", err)
        }

        defer jsonFile.Close()

        jsonBytes, err := ioutil.ReadAll(jsonFile)
        if err != nil {
            return newip, "",fmt.Errorf("LoadIPAMConfig Flatfile - ioutil.ReadAll error: %s", err)
        }

        if err := json.Unmarshal(jsonBytes, &ipamProv); err != nil {
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

