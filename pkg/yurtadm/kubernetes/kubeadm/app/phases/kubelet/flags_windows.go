//go:build windows
// +build windows

/*
Copyright 2020 The Kubernetes Authors.

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

package kubelet

import "github.com/openyurtio/openyurt/pkg/yurtadm/cmd/join/joindata"

// buildKubeletArgMap takes a kubeletFlagsOpts object and builds based on that a string-string map with flags
// that should be given to the local Windows kubelet daemon.
func buildKubeletArgMap(data joindata.YurtJoinData) map[string]string {
	return buildKubeletArgMapCommon(data)
}
