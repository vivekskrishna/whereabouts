/*
Copyright 2016 The Kubernetes Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Note: the example only works with the code within the same release/branch.
package podData

import (
	//"context"
	"flag"
	//"fmt"
	//"path/filepath"
	"strings"
	//"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"github.com/dougbtv/whereabouts/pkg/types"
	"github.com/dougbtv/whereabouts/pkg/logging"
	//
	// Uncomment to load all auth plugins
	// _ "k8s.io/client-go/plugin/pkg/client/auth"
	//
	// Or uncomment to load specific auth plugins
	// _ "k8s.io/client-go/plugin/pkg/client/auth/azure"
	// _ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	// _ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
	// _ "k8s.io/client-go/plugin/pkg/client/auth/openstack"
)

func GetPodAnnotation(ipamConf types.IPAMConfig, podRef string) (string) {
	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", ipamConf.Kubernetes.KubeConfigPath, "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", ipamConf.Kubernetes.KubeConfigPath, "absolute path to the kubeconfig file")
	}
	flag.Parse()

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		logging.Errorf("error in buildconfig")
		return podRef
	}

	// create the clientset
	logging.Debugf("newforconfig")
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		logging.Errorf("error in newforconfig")
		return podRef
	}
	for {
		pods, err1 := clientset.CoreV1().Pods("").List( metav1.ListOptions{})
		if err1 != nil {
			logging.Errorf("error in reading pod data %s", err1)
			return podRef
		}
		logging.Debugf("There are %d pods in the cluster\n", len(pods.Items))

		// Examples for error handling:
		// - Use helper functions like e.g. errors.IsNotFound()
		// - And/or cast to StatusError and use its properties like e.g. ErrStatus.Message
		podRefVal := strings.Split(podRef, "/")
		namespace := podRefVal[0]
		pod := podRefVal[1]
		poddata, err := clientset.CoreV1().Pods(namespace).Get(pod, metav1.GetOptions{})
		if errors.IsNotFound(err) {
			logging.Errorf("Pod %s in namespace %s not found\n", pod, namespace)
		} else if statusError, isStatus := err.(*errors.StatusError); isStatus {
			logging.Debugf("Error getting pod %s in namespace %s: %v\n",
				pod, namespace, statusError.ErrStatus.Message)
		} else if err != nil {
			logging.Errorf("Got error for pod annotation search %s",err)
			return podRef
		} else {
			logging.Debugf("Found pod %s in namespace %s with data %s\n", pod, namespace,poddata.ObjectMeta.Annotations)
			for annoName,annoVal := range poddata.ObjectMeta.Annotations {
				if annoName == "podname" {
					podRef = annoVal
					logging.Debugf("found pod with annotation name podname with value %s",annoVal)
				}
			}
		}
		return podRef

	}
}
