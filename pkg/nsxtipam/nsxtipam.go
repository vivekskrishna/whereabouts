package nsxtipam
import (
	"fmt"
	"net"
	"time"
	"net/http"
	"errors"
	"crypto/tls"
	"net/url"
	"os"
        "io/ioutil"
	"strings"
        "strconv"

	//"github.com/dougbtv/whereabouts/pkg/allocate"
        cnitypes "github.com/containernetworking/cni/pkg/types"
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

type SubnetIPList struct {
	SList	   []string      `json:"iplist"`
}
type IPAMPlug struct {
        Type       string        `json:"ipamtype,omitempty"`
        Url        string        `json:"ipamurl,omitempty"`
	AppID      string        `json:"appid,omitempty"`
        Username   string        `json:"ipamuser,omitempty"`
        Password   string        `json:"ipampwd,omitempty"`
}

//json data for session authentication with NSX-T manager
type SessionAuthentication struct {
	Username	string	`json:"j_username,omitempty"`
       	Password	string	`json:"j_password,omitempty"` 
}

//parsing nsxt segment data for getting def gw, pool id, static routes etc
// generated using https://mholt.github.io/json-to-go/
type SegmentData struct {
	Type    string `json:"type"`
	Subnets []struct {
		GatewayAddress string   `json:"gateway_address"`
		DhcpRanges     []string `json:"dhcp_ranges"`
		DhcpConfig     struct {
			Options struct {
				Option121 struct {
					StaticRoutes []struct {
						Network string `json:"network"`
						NextHop string `json:"next_hop"`
					} `json:"static_routes"`
				} `json:"option121"`
			} `json:"options"`
			ResourceType  string `json:"resource_type"`
			ServerAddress string `json:"server_address"`
			LeaseTime     int    `json:"lease_time"`
		} `json:"dhcp_config"`
		Network string `json:"network"`
	} `json:"subnets,omitempty"`
	TransportZonePath string `json:"transport_zone_path,omitempty"`
	AdvancedConfig    struct {
		AddressPoolPaths []string `json:"address_pool_paths"`
		Hybrid           bool     `json:"hybrid"`
		InterRouter      bool     `json:"inter_router"`
		LocalEgress      bool     `json:"local_egress"`
		UrpfMode         string   `json:"urpf_mode"`
		Connectivity     string   `json:"connectivity"`
	} `json:"advanced_config,omitempty"`
	AdminState       string `json:"admin_state"`
	ResourceType     string `json:"resource_type"`
	ID               string `json:"id"`
	DisplayName      string `json:"display_name"`
	Path             string `json:"path,omitempty"`
	RelativePath     string `json:"relative_path,omitempty"`
	ParentPath       string `json:"parent_path,omitempty"`
	UniqueID         string `json:"unique_id,omitempty"`
	MarkedForDelete  bool   `json:"marked_for_delete,omitempty"`
	Overridden       bool   `json:"overridden,omitempty"`
}

type IpPool struct {
	ResourceType     string `json:"resource_type,omitempty"`
	ID               string `json:"id,omitempty"`
	DisplayName      string `json:"display_name,omitempty"`
	Path             string `json:"path,omitempty"`
	RelativePath     string `json:"relative_path,omitempty"`
	ParentPath       string `json:"parent_path,omitempty"`
	UniqueID         string `json:"unique_id,omitempty"`
	MarkedForDelete  bool   `json:"marked_for_delete,omitempty"`
	Overridden       bool   `json:"overridden,omitempty"`
}

type IpSubnet struct {
	Results []struct {
		Cidr             string   `json:"cidr,omitempty"`
		GatewayIP        string   `json:"gateway_ip,omitempty"`
		DNSNameservers   []string `json:"dns_nameservers,omitempty"`
		AllocationRanges []struct {
			Start string `json:"start"`
			End   string `json:"end"`
		} `json:"allocation_ranges,omitempty"`
		ResourceType     string `json:"resource_type"`
		ID               string `json:"id"`
		DisplayName      string `json:"display_name"`
		Path             string `json:"path"`
		RelativePath     string `json:"relative_path"`
		ParentPath       string `json:"parent_path"`
		UniqueID         string `json:"unique_id"`
		MarkedForDelete  bool   `json:"marked_for_delete"`
		Overridden       bool   `json:"overridden"`
	} `json:"results,omitempty"`
	ResultCount   int    `json:"result_count,omitempty"`
	SortBy        string `json:"sort_by,omitempty"`
	SortAscending bool   `json:"sort_ascending,omitempty"`
}

type PoolData struct {
	PoolUsage struct {
		TotalIds     int `json:"total_ids"`
		AllocatedIds int `json:"allocated_ids"`
		FreeIds      int `json:"free_ids"`
	} `json:"pool_usage"`
	Subnets []struct {
		Cidr             string   `json:"cidr"`
		GatewayIP        string   `json:"gateway_ip,omitempty"`
		DNSNameservers   []string `json:"dns_nameservers,omitempty"`
		AllocationRanges []struct {
			Start string `json:"start"`
			End   string `json:"end"`
		} `json:"allocation_ranges,omitempty"`
	} `json:"subnets"`
	ResourceType string `json:"resource_type"`
	ID           string `json:"id"`
	DisplayName  string `json:"display_name"`
	Tags         []struct {
		Scope string `json:"scope"`
		Tag   string `json:"tag"`
	} `json:"tags,omitempty"`
}

type PoolsData struct {
	Results       []PoolData	`json:"results,omitempty"`
	ResultCount   int       `json:"result_count"`
}

type Allocate struct {
	AllocationID *string `json:"allocation_id"`
}

type AllocatePool struct {
	AllocationIP     string `json:"allocation_ip,omitempty"`
	ResourceType     string `json:"resource_type,omitempty"`
	ID               string `json:"id,omitempty"`
	DisplayName      string `json:"display_name,omitempty"`
	Path             string `json:"path,omitempty"`
	RelativePath     string `json:"relative_path,omitempty"`
	ParentPath       string `json:"parent_path,omitempty"`
	UniqueID         string `json:"unique_id,omitempty"`
	MarkedForDelete  bool   `json:"marked_for_delete,omitempty"`
	Overridden       bool   `json:"overridden,omitempty"`
}

//end of generated data

func getCredentials(ipam IPAMPlug) (*http.Cookie, string, error) {
    //authenticates with NSX-T and gets the cookia for the session
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    } 
    client := &http.Client{
	Timeout: time.Second * 5, Transport: tr,
    }

    apiUrl := "https://" + ipam.Url
    resource := "/api/session/create"
    data := url.Values{}
    data.Set("j_username", ipam.Username)
    data.Add("j_password", ipam.Password)

    u, _ := url.ParseRequestURI(apiUrl)
    u.Path = resource
    u.RawQuery = data.Encode()
    urlString := fmt.Sprintf("%v", u)

    var nil_cookie *http.Cookie
    req, err := http.NewRequest("POST", urlString, nil)
    
    req.Header.Set("Content-Type", "application/x-ww-form-urlencoded")
    req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
    if err != nil {
	return nil_cookie, "", fmt.Errorf("Got error %s", err.Error())
    }

    resp, err := client.Do(req)
    if err != nil {
	return nil_cookie, "", fmt.Errorf("Got error %s", err.Error())
    }  
    defer resp.Body.Close()
    body, _ := ioutil.ReadAll(resp.Body)
    if resp.StatusCode == 200 {
        xsrf_token := ""
        for k, v := range resp.Header {
          if strings.ToLower("X-XSRF-TOKEN") == strings.ToLower(k) {
		xsrf_token = v[0]
	  }
        }
        for _,cookie := range resp.Cookies() {
        	return cookie, xsrf_token, err
	}

    } 
    logging.Errorf("Response code is %s and %s", resp.StatusCode, resp)
    logging.Errorf("Response body is %s", body)
    return nil_cookie, "", err
}

func checkExistingAllocation(token1 *http.Cookie, xsrf_token string, ipam IPAMPlug, pod string, poolPath string) (string) {
	//we will check in teh segment pool if there is a entry in the segment pool for the pod ref. the pod ref is the ID
	urlstring := "https://" + ipam.Url + "/policy/api/v1" + poolPath + "/ip-allocations/" + pod
        tr := &http.Transport{
          TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        }
        client := &http.Client{Transport: tr}
        req, _ := http.NewRequest("GET", urlstring, nil)
        req.AddCookie(token1)
        req.Header.Add("X-XSRF-TOKEN",xsrf_token)
        resp, _ := client.Do(req)
        defer resp.Body.Close()
	var segData AllocatePool
        if resp.StatusCode == 200 {
                body, _ := ioutil.ReadAll(resp.Body)
                if err := json.Unmarshal(body, &segData); err != nil {
                        logging.Errorf("json decoding failure of %s with error %s",body,err)
                        return ""
                }
		
                logging.Debugf("pod %s already has an allocation with IP %s",pod, segData.AllocationIP)
		return segData.AllocationIP
	}
	logging.Debugf("Pod %s has no existing allocation",pod)
	return ""
}

func allocateIPFromPool(token1 *http.Cookie, xsrf_token string, ipam IPAMPlug, pod string , poolID string) (string) {
	//we will allocate an ip from ip pool using its pool id, as we need auto allocation.
        //to do, we need to support static ip if possible
	urlstring := "https://" + ipam.Url + "/api/v1/pools/ip-pools/" + poolID + "?action=ALLOCATE"
        tr := &http.Transport{
          TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    	}
        client := &http.Client{Transport: tr}
	var AllocData Allocate
	AllocData.AllocationID = nil	
	alloc_json,_ := json.Marshal(AllocData)
        req_body := strings.NewReader(string(alloc_json))
        req, _ := http.NewRequest("POST", urlstring, req_body)
        req.AddCookie(token1)
        req.Header.Add("X-XSRF-TOKEN",xsrf_token)
        req.Header.Add("Content-Type","application/json")
        resp, _ := client.Do(req)
        //logging.Debugf("Request is %s with body %s \n response is %s ", req,req_body, resp)
        defer resp.Body.Close()
        if resp.StatusCode == 200 {
                body, _ := ioutil.ReadAll(resp.Body)
                if err := json.Unmarshal(body, &AllocData); err != nil {
                        logging.Errorf("json decoding failure of %s with error %s",body,err)
                        return ""
                }

                logging.Debugf("pod %s allocated IP %s", pod, *AllocData.AllocationID)
		return *AllocData.AllocationID
        }
	body, _ := ioutil.ReadAll(resp.Body)
        logging.Debugf("Pod %s IP Allocation failed with response body %s",body)
        return ""
}

func deallocateIPFromPool(token1 *http.Cookie, xsrf_token string, ipam IPAMPlug, pod string , poolID string, podip string) (string) {
        //we will de-allocate an ip from ip pool using its pool id, as we need auto allocation.
        //to do, we need to support static ip if possible
        urlstring := "https://" + ipam.Url + "/api/v1/pools/ip-pools/" + poolID + "?action=RELEASE"
        tr := &http.Transport{
          TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    	}
        client := &http.Client{Transport: tr}
        var AllocData Allocate
	AllocData.AllocationID = &podip
        alloc_json,_ := json.Marshal(AllocData)
        req_body := strings.NewReader(string(alloc_json))
        req, _ := http.NewRequest("POST", urlstring, req_body)
        req.AddCookie(token1)
        req.Header.Add("X-XSRF-TOKEN",xsrf_token)
        req.Header.Add("Content-Type","application/json")
        resp, _ := client.Do(req)
        defer resp.Body.Close()
        if resp.StatusCode == 200 {
                body, _ := ioutil.ReadAll(resp.Body)
                if err := json.Unmarshal(body, &AllocData); err != nil {
                        logging.Errorf("json decoding failure of %s with error %s",body,err)
                        return ""
                }

                logging.Debugf("pod %s de-allocated IP %s", pod, *AllocData.AllocationID)
                return *AllocData.AllocationID
        }
        logging.Debugf("Pod %s IP Allocation failed")
        return ""
}

func NSXSegmentAllocation(token1 *http.Cookie, xsrf_token string, ipam IPAMPlug, poolPath string, pod string, pod_ip string, operation string) (error) {
	// we will update the segment pool with the podref and the ip allocated from pool. this will be the DB of ultimate truth
        urlstring := "https://" + ipam.Url + "/policy/api/v1" + poolPath + "/ip-allocations/" + pod
        tr := &http.Transport{
          TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    	}
        client := &http.Client{Transport: tr}
        var AllocData AllocatePool
	http_method :="PUT"
	if operation == "delete" || operation == "DELETE" {
		http_method = "DELETE"
	} else {	
		AllocData.AllocationIP = pod_ip
	}
        alloc_json,_ := json.Marshal(AllocData)
        req_body := strings.NewReader(string(alloc_json))
        req, _ := http.NewRequest(http_method, urlstring, req_body)
        req.AddCookie(token1)
        req.Header.Add("X-XSRF-TOKEN",xsrf_token)
        req.Header.Add("Content-Type","application/json")
        resp, _ := client.Do(req)
        defer resp.Body.Close()
        if resp.StatusCode == 200 {
                body, err := ioutil.ReadAll(resp.Body)
                if err := json.Unmarshal(body, &AllocData); err != nil {
                        logging.Errorf("json decoding failure of %s with error %s",body,err)
                        return err
                }
		if  AllocData.AllocationIP == pod_ip {
                	logging.Debugf("pod %s allocated IP %s", pod, AllocData.AllocationIP)
                	return err
		}
        }
        logging.Debugf("Request is %s with body %s \n response is %s ", req,req_body, resp)
        logging.Debugf("Pod %s IP Allocation failed",pod)
        return errors.New("Error in Allocation")
}

//function to allocate an IP for a request from a pod for secondary IP
func allocateIP(token1 *http.Cookie, xsrf_token string, ipam IPAMPlug, pod string , segment string) (net.IPNet, string, []*cnitypes.Route, error) {
        //pool name is treated as segment name in nsx-t
        //we assume a pool is associated with a nsx segment and also that dhcp is configured with static routes so that we can grab gateway and static routes from segment dhcp config
	var newip net.IPNet
	// First we will get the segment to make sure we have the subnet of interest and also get the Defalt GW for that subnet ID
	tr := &http.Transport{
          TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    	}
        urlstring := "https://" + ipam.Url + "/policy/api/v1/infra/segments/" + segment
	client := &http.Client{Transport: tr}
        req, _ := http.NewRequest("GET", urlstring, nil)
        req.AddCookie(token1)
        req.Header.Add("X-XSRF-TOKEN",xsrf_token)
        resp, _ := client.Do(req)
	defer resp.Body.Close()
	var segData SegmentData
	var gw string
	var subnet_mask string
	var ip_routes []*cnitypes.Route
        //logging.Debugf("Request is %s \n response is %s ", req, resp)
	if resp.StatusCode == 200 {
        	body, err := ioutil.ReadAll(resp.Body)
        	//logging.Debugf("Body is %s and %d",body,resp.StatusCode)
        	//var tok IPAMToken
        	if err := json.Unmarshal(body, &segData); err != nil {
			logging.Errorf("json decoding failure of %s with error %s",body,err)
                	return newip,"", ip_routes, err
        	}
		logging.Debugf("decoded data is %v",segData)
		
		//poolPath will have the name of ip pool in following format "infra/ip-pools/segment1"
		poolPath := segData.AdvancedConfig.AddressPoolPaths[0]
		gw = segData.Subnets[0].GatewayAddress
		tmp1 := strings.Split(gw,"/")
		gw = tmp1[0]
		opt121_list := segData.Subnets[0].DhcpConfig.Options.Option121.StaticRoutes
		ntwk :=  segData.Subnets[0].Network
		tmp1 = strings.Split(ntwk, "/")	
		subnet_mask = tmp1[1]
		for i := range opt121_list {
			var ipr net.IPNet
			//for each static route entry, convert from string to IPNet
			ipNet := opt121_list[i]
                        _,newip1,_ := net.ParseCIDR(ipNet.Network)
			tmp1 = strings.Split(ipNet.Network, "/")
                        ipr.IP = net.ParseIP(tmp1[0])
                        ipr.Mask = newip1.Mask	
			ipgw := net.ParseIP(ipNet.NextHop)
			var route_entry cnitypes.Route
			route_entry.Dst = ipr
			route_entry.GW = ipgw
			ip_routes = append(ip_routes, &route_entry)
		}
		logging.Debugf("poolpath for segment %s is %s with def gw %s and routes %s",segment,poolPath,gw,ip_routes)


		// getting the pool id from the pool data using poolPath
                // api used here is 
		logging.Debugf("Hello there")
		// check if a entry already exists for the podRef
		tr := &http.Transport{
        	  TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    		}
		urlstring1 := "https://" + ipam.Url + "/api/v1/pools/ip-pools"
                client1 := &http.Client{Transport: tr}
                req1, _ := http.NewRequest("GET", urlstring1, nil)
		req1.AddCookie(token1)
                req1.Header.Add("X-XSRF-TOKEN",xsrf_token)
                resp1, _ := client1.Do(req1)
                //logging.Debugf("Request is %s \n response is %s ", req1, resp1)
                defer resp1.Body.Close()
                var poolList PoolsData
                if resp1.StatusCode != 200 {
			logging.Errorf("response code is %s", resp1.StatusCode)
                        return newip, "",ip_routes, fmt.Errorf("error")
                }
                body, _ = ioutil.ReadAll(resp1.Body)
                if err := json.Unmarshal(body, &poolList); err != nil {
                        logging.Errorf("json decoding failure of %s with error %s",body,err)
                        return newip,"", ip_routes, err
                }
             	if poolList.ResultCount == 0 {
			logging.Errorf("In func allocateIP , No ip pools found configured in NSX-T")
                        return newip,"", ip_routes, err
                } 
		//checking all pool id to check which is the pool configured in segment
		pool_id := ""
		for _, poolData := range  poolList.Results {
			for _, tags := range poolData.Tags {
				//grabbing pool_id for the pool path of interest
				if tags.Scope == "policyPath"  && tags.Tag == poolPath{
					pool_id = poolData.ID
				}	
			}
		}	
		if pool_id == "" {
			//for some reason we couldnt find the pool ID for pool configured in segment, return error
			logging.Errorf("In func allocateIP , No ip pool ID found configured in NSX-T")
                        return newip,"", ip_routes, err
		}
                logging.Debugf("Pool ID for poolPath %s is %s", poolPath, pool_id)
		//check if the pod already has an IP and if so return it
		var pod_ip string
		pod_ip = checkExistingAllocation(token1, xsrf_token, ipam, pod, poolPath)
		if pod_ip != "" {
		// we have an existing entry to this pod Ref. we will return IP in our record. the above func checkExistingAllocation will check enry existings in both segment pool and in ip pool so that the ip is indeed reserved, else it will free up old reservation in segment pool and we will proceed with new ip assigmen below. we always assume the ip in ip pool is source of truth.
			logging.Debugf(" IP %s already allocated for pod %s",pod_ip, pod)
                        ipNet := pod_ip + "/" + subnet_mask
                        _,newip1,_ := net.ParseCIDR(ipNet)
                        newip.IP = net.ParseIP(pod_ip)
                        newip.Mask = newip1.Mask

                        return newip, gw ,ip_routes, nil
		}

		// now we allocate an IP, first we will allocate an IP from the pool
		pod_ip = allocateIPFromPool(token1, xsrf_token, ipam, pod, pool_id)

		if pod_ip == "" {
			//return error
                        logging.Errorf("pod ip returned for pod %s is %s", pod, pod_ip)
			return newip, "", ip_routes, err
		}

		//create a new entry in the segment pool for the Pod with teh IP allcoated from IP pool
		NSXSegmentAllocation(token1, xsrf_token, ipam, poolPath, pod, pod_ip, "create")

		//now we can return the allocated ip along with other constructs
		logging.Debugf("Checking resp for allocated IP for pod")
		subnet_mask = "24"
                if pod_ip != "" {
                        logging.Debugf(" IP %s already allocated for pod %s",pod_ip, pod)
                        ipNet := pod_ip + "/" + subnet_mask
                        _,newip1,_ := net.ParseCIDR(ipNet)
                        newip.IP = net.ParseIP(pod_ip)
                        newip.Mask = newip1.Mask

                        return newip, gw ,ip_routes, nil 
                }
        	return newip,gw, ip_routes, err
        }
        body, _ := ioutil.ReadAll(resp.Body)
        logging.Errorf("Response Body is %s", body)
        return newip, "",ip_routes, fmt.Errorf("error")
}

//function to allocate an IP for a request from a pod for secondary IP
func deallocateIP(token1 *http.Cookie, xsrf_token string, ipam IPAMPlug, pod string , segment string) (net.IPNet, string, []*cnitypes.Route, error) {
        //pool name is treated as segment name in nsx-t
        //we assume a pool is associated with a nsx segment and also that dhcp is configured with static routes so that we can grab gateway and static routes from segment dhcp config
	var newip net.IPNet
	// First we will get the segment to make sure we have the subnet of interest and also get the Defalt GW for that subnet ID
        urlstring := "https://" + ipam.Url + "/policy/api/v1/infra/segments/" + segment
	tr := &http.Transport{
          TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    	}
	client := &http.Client{Transport: tr}
        req, _ := http.NewRequest("GET", urlstring, nil)
        req.AddCookie(token1)
        req.Header.Add("X-XSRF-TOKEN",xsrf_token)
        resp, _ := client.Do(req)
	defer resp.Body.Close()
	var segData SegmentData
	var gw string
	var subnet_mask string
	var ip_routes []*cnitypes.Route
	if resp.StatusCode == 200 {
        	body, err := ioutil.ReadAll(resp.Body)
        	//logging.Debugf("Body is %s and %d",body,resp.StatusCode)
        	//var tok IPAMToken
        	if err := json.Unmarshal(body, &segData); err != nil {
			logging.Errorf("json decoding failure of %s with error %s",body,err)
                	return newip,"", ip_routes, err
        	}
		logging.Debugf("decoded data is %v",segData)
		
		//poolPath will have the name of ip pool in following format "infra/ip-pools/segment1"
		poolPath := segData.AdvancedConfig.AddressPoolPaths[0]
		gw = segData.Subnets[0].GatewayAddress
		tmp1 := strings.Split(gw,"/")
		gw = tmp1[0]
		opt121_list := segData.Subnets[0].DhcpConfig.Options.Option121.StaticRoutes
		ntwk :=  segData.Subnets[0].Network
		tmp1 = strings.Split(ntwk, "/")	
		subnet_mask = tmp1[1]
		for i := range opt121_list {
			var ipr net.IPNet
			//for each static route entry, convert from string to IPNet
			ipNet := opt121_list[i]
                        _,newip1,_ := net.ParseCIDR(ipNet.Network)
			tmp1 = strings.Split(ipNet.Network, "/")
                        ipr.IP = net.ParseIP(tmp1[0])
                        ipr.Mask = newip1.Mask	
			ipgw := net.ParseIP(ipNet.NextHop)
			var route_entry cnitypes.Route
			route_entry.Dst = ipr
			route_entry.GW = ipgw
			ip_routes = append(ip_routes, &route_entry)
		}
		//logging.Debugf("id for segment %s is %s with def gw %s and subnet %s/%s",segment,id,gw,sn,mask)


		// getting the pool id from the pool data using poolPath
                // api used here is 
		logging.Debugf("Hello there")
		// check if a entry already exists for the podRef
		urlstring1 := "https://" + ipam.Url + "/api/v1/pools/ip-pools"
		tr := &http.Transport{
        	  TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    		}
                client1 := &http.Client{Transport: tr}
                req1, _ := http.NewRequest("GET", urlstring1, nil)
		req1.AddCookie(token1)
                req1.Header.Add("X-XSRF-TOKEN",xsrf_token)
                resp1, _ := client1.Do(req1)
                defer resp1.Body.Close()
                var poolList PoolsData
                if resp1.StatusCode != 200 {
			logging.Errorf("response code is %s", resp1.StatusCode)
                        return newip, "",ip_routes, fmt.Errorf("error")
                }
                body, _ = ioutil.ReadAll(resp1.Body)
                if err := json.Unmarshal(body, &poolList); err != nil {
                        logging.Errorf("json decoding failure of %s with error %s",body,err)
                        return newip,"", ip_routes, err
                }
             	if poolList.ResultCount == 0 {
			logging.Errorf("In func allocateIP , No ip pools found configured in NSX-T")
                        return newip,"", ip_routes, err
                } 
		//checking all pool id to check which is the pool configured in segment
		pool_id := ""
		for _, poolData := range  poolList.Results {
			for _, tags := range poolData.Tags {
				//grabbing pool_id for the pool path of interest
				if tags.Scope == "policyPath"  && tags.Tag == poolPath{
					pool_id = poolData.ID
				}	
			}
		}	
		if pool_id == "" {
			//for some reason we couldnt find the pool ID for pool configured in segment, return error
			logging.Errorf("In func allocateIP , No ip pool ID found configured in NSX-T")
                        return newip,"",ip_routes, err
		}
		//check if the pod already has an IP and if so return it
		var pod_ip string
		pod_ip = checkExistingAllocation(token1, xsrf_token, ipam, pod, poolPath)
		if pod_ip == "" {
		//no existing allocation found for the pod, we will return error
		// return error
		}

		// now we de-allocate an IP, first we will allocate an IP from the pool
		pod_ip = deallocateIPFromPool(token1, xsrf_token, ipam, pod, pool_id, pod_ip)

		if pod_ip == "" {
			//return error
			return newip, "", ip_routes, err
		}

		//create a new entry in the segment pool for the Pod with teh IP allcoated from IP pool
		NSXSegmentAllocation(token1, xsrf_token, ipam, poolPath, pod, pod_ip, "delete")

		//now we can return the allocated ip along with other constructs
		logging.Debugf("Checking resp for allocated IP for pod")
		subnet_mask = "24"
                if pod_ip != "" {
                        logging.Debugf(" IP %s already allocated for pod %s",pod_ip, pod)
                        ipNet := pod_ip + "/" + subnet_mask
                        _,newip1,_ := net.ParseCIDR(ipNet)
                        newip.IP = net.ParseIP(pod_ip)
                        newip.Mask = newip1.Mask

                        return newip, gw ,ip_routes, nil 
                }
        	return newip,gw,ip_routes, err
        }
        return newip, "",ip_routes,fmt.Errorf("error")
}

// IPManagement manages ip allocation and deallocation from a storage perspective
func IPManagement(mode int, ipamConf types.IPAMConfig, containerID string, podRef string) (net.IPNet, string, []*cnitypes.Route, error) {

	logging.Debugf("IPManagement for nsxt-ipam -- mode: %v / host: %v / containerID: %v / podRef: %v", mode, ipamConf.EtcdHost, containerID, podRef)

	var newip net.IPNet
	var route_list []*cnitypes.Route
	ipamProv := IPAMPlug{}

        jsonFile, err := os.Open("/etc/cni/net.d/whereabouts.d/whereabouts-ipam.conf")

        if err != nil {
            logging.Debugf("1")	
            return newip, "",route_list, fmt.Errorf("Error opening flat configuration file %s", err)
        }

        defer jsonFile.Close()

        jsonBytes, err := ioutil.ReadAll(jsonFile)
        if err != nil {
            logging.Debugf("2")
            return newip, "", route_list, fmt.Errorf("LoadIPAMConfig Flatfile - ioutil.ReadAll error: %s", err)
        }

        if err := json.Unmarshal(jsonBytes, &ipamProv); err != nil {
            logging.Debugf("3")
            return newip, "", route_list, fmt.Errorf("LoadIPAMConfig Flatfile - JSON Parsing Error: %s / bytes: %s", err, jsonBytes)
        } 

	logging.Debugf("IpamProv is %s and decoded is %v",jsonBytes, ipamProv)
	cookie, xsrf_token, err := getCredentials(ipamProv)
        logging.Debugf("The credential token is %s and cookie is %s",xsrf_token, cookie)
        //return newip, "dummy", route_list, err
	podRef = podData.GetPodAnnotation(ipamConf, podRef)
        podRef = strings.Replace(podRef, "/", "-", -1)
	logging.Debugf("podref after annotation search is %s",podRef)
	switch mode {
	case types.Allocate:
            return allocateIP(cookie, xsrf_token, ipamProv, podRef, ipamConf.Pool)            	
	case types.Deallocate:
            return deallocateIP(cookie, xsrf_token, ipamProv, podRef, ipamConf.Pool)
	default:
	    logging.Errorf("Unknown mode of operation")
	}
	return newip, "dummy", route_list, err
}

/*func main() {
	ipamConf.Kubernetes.KubeConfigPath = "/etc/cni/net.d/whereabouts.d/whereabouts.kubeconfig"
	fmt.Println("Hello, playground")
	//ip1,gw, _ := IPManagement(0,ipamConf,"dummy","default/test-5d68d4fdf6-pdmbr")
	//logging.Debugf("At main after allocate is %s with gw %s",string(ip1.IP),gw)
        IPManagement(1,ipamConf,"dummy","default/test-5d68d4fdf6-pdmbr")
}*/

