package main

import (
	"fmt"
	"strings"
	"net"
        "os"
	"io/ioutil"
        "encoding/json"
	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/dougbtv/whereabouts/pkg/allocate"
	"github.com/dougbtv/whereabouts/pkg/config"
	"github.com/dougbtv/whereabouts/pkg/logging"
	//"github.com/dougbtv/whereabouts/pkg/storage"
	"github.com/dougbtv/whereabouts/pkg/openwisp"
	"pkg/phpipam"
	"github.com/dougbtv/whereabouts/pkg/types"
)

type IPAMPlug struct {
        Type       string        `json:"ipamtype,omitempty"`
        Url        string        `json:"ipamurl,omitempty"`
        Username   string        `json:"ipamuser,omitempty"`
        Password   string        `json:"ipampwd,omitempty"`
}


func main() {
	// TODO: implement plugin version
	skel.PluginMain(cmdAdd, cmdGet, cmdDel, version.All, "TODO")
}

func cmdGet(args *skel.CmdArgs) error {
	// TODO
	return fmt.Errorf("CNI GET method is not implemented")
}

func cmdAdd(args *skel.CmdArgs) error {
	ipamConf, confVersion, err := config.LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		logging.Errorf("IPAM configuration load failed: %s", err)
		return err
	}
	logging.Debugf("ADD - IPAM configuration successfully read: %+v", filterConf(*ipamConf))
	logging.Debugf("ADD - Input parameters were %s and %s", args.StdinData, ipamConf.Pool )

	// Initialize our result, and assign DNS & routing.
	result := &current.Result{}
	result.DNS = ipamConf.DNS
	result.Routes = ipamConf.Routes

        ipamProv := IPAMPlug{}
	jsonFile, err := os.Open("/etc/cni/net.d/whereabouts.d/whereabouts-ipam.conf")

        if err != nil {
            logging.Debugf("1")
            return fmt.Errorf("Error opening flat configuration file %s", err)
        }

        defer jsonFile.Close()

        jsonBytes, err := ioutil.ReadAll(jsonFile)
        if err != nil {
            return fmt.Errorf("LoadIPAMConfig Flatfile - ioutil.ReadAll error: %s", err)
        }

        if err := json.Unmarshal(jsonBytes, &ipamProv); err != nil {
            return fmt.Errorf("LoadIPAMConfig Flatfile - JSON Parsing Error: %s / bytes: %s", err, jsonBytes)
        }

	logging.Debugf("Beginning IPAM for ContainerID: %v", args.ContainerID)
	//newip, err := storage.IPManagement(types.Allocate, *ipamConf, args.ContainerID, getPodRef(args.Args))
	newip, gw1, err := openwisp.IPManagement(types.Allocate, *ipamConf, args.ContainerID, getPodRef(args.Args))
	ipamConf.Gateway = net.ParseIP(gw1)


	if err != nil {
		logging.Errorf("Error at storage engine: %s", err)
		return fmt.Errorf("Error at storage engine: %w", err)
	}


	// Determine if v4 or v6.
	var useVersion string
	if allocate.IsIPv4(newip.IP) {
		useVersion = "4"
	} else {
		useVersion = "6"
	}

	result.IPs = append(result.IPs, &current.IPConfig{
		Version: useVersion,
		Address: newip,
		Gateway: ipamConf.Gateway})

	logging.Debugf("IP is %s",result.IPs)
	// Assign all the static IP elements.
	for _, v := range ipamConf.Addresses {
		result.IPs = append(result.IPs, &current.IPConfig{
			Version: v.Version,
			Address: v.Address,
			Gateway: v.Gateway})
	}
	return cnitypes.PrintResult(result, confVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	ipamConf, _, err := config.LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		logging.Errorf("IPAM configuration load failed: %s", err)
		return err
	}
	logging.Debugf("DEL - IPAM configuration successfully read: %+v", filterConf(*ipamConf))
	logging.Debugf("ContainerID: %v", args.ContainerID)

	//_, err = storage.IPManagement(types.Deallocate, *ipamConf, args.ContainerID, getPodRef(args.Args))
	_,_,err = openwisp.IPManagement(types.Deallocate, *ipamConf, args.ContainerID, getPodRef(args.Args))
	if err != nil {
		logging.Verbosef("WARNING: Problem deallocating IP: %s", err)
		// return fmt.Errorf("Error deallocating IP: %s", err)
	}

	return nil
}

func filterConf(conf types.IPAMConfig) types.IPAMConfig {
	new := conf
	new.EtcdPassword = "*********"
	return new
}

// GetPodRef constructs the PodRef string from CNI arguments.
// It returns an empty string, if K8S_POD_NAMESPACE & K8S_POD_NAME arguments are not provided.
func getPodRef(args string) string {
	podNs := ""
	podName := ""

	for _, arg := range strings.Split(args, ";") {
		if strings.HasPrefix(arg, "K8S_POD_NAMESPACE=") {
			podNs = strings.TrimPrefix(arg, "K8S_POD_NAMESPACE=")
		}
		if strings.HasPrefix(arg, "K8S_POD_NAME=") {
			podName = strings.TrimPrefix(arg, "K8S_POD_NAME=")
		}
	}

	if podNs != "" && podName != "" {
		return podNs + "/" + podName
	}
	return ""
}
