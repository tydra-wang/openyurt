/*
Copyright 2021 The OpenYurt Authors.

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

package network

import (
	"strings"

	"k8s.io/klog"
	"k8s.io/kubernetes/pkg/util/iptables"
	"k8s.io/utils/exec"
	utilnet "k8s.io/utils/net"
)

type iptablesRule struct {
	pos   iptables.RulePosition
	table iptables.Table
	chain iptables.Chain
	args  []string
}

type IptablesManager struct {
	iptables iptables.Interface
	rules    []iptablesRule
}

func NewIptablesManager(dummyIfIP, dummyIfPort string) *IptablesManager {
	protocol := iptables.ProtocolIpv4
	if utilnet.IsIPv6String(dummyIfIP) {
		protocol = iptables.ProtocolIpv6
	}
	execer := exec.New()
	iptInterface := iptables.New(execer, protocol)

	im := &IptablesManager{
		iptables: iptInterface,
		rules:    makeupIptablesRules(dummyIfIP, dummyIfPort),
	}

	return im
}

func makeupIptablesRules(ifIP, ifPort string) []iptablesRule {
	loopbackAddr := "127.0.0.1"
	if utilnet.IsIPv6String(ifIP) {
		loopbackAddr = "::1"
	}
	return []iptablesRule{
		// skip connection track for traffic from container to 169.254.2.1:10261
		{iptables.Prepend, iptables.Table("raw"), iptables.ChainPrerouting, []string{"-p", "tcp", "--dport", ifPort, "--destination", ifIP, "-j", "NOTRACK"}},
		// skip connection track for traffic from host network to 169.254.2.1:10261
		{iptables.Prepend, iptables.Table("raw"), iptables.ChainOutput, []string{"-p", "tcp", "--dport", ifPort, "--destination", ifIP, "-j", "NOTRACK"}},
		// accept traffic to 169.254.2.1:10261
		{iptables.Prepend, iptables.TableFilter, iptables.ChainInput, []string{"-p", "tcp", "-m", "comment", "--comment", "for container access hub agent", "--dport", ifPort, "--destination", ifIP, "-j", "ACCEPT"}},
		// skip connection track for traffic from 169.254.2.1:10261
		{iptables.Prepend, iptables.Table("raw"), iptables.ChainOutput, []string{"-p", "tcp", "--sport", ifPort, "-s", ifIP, "-j", "NOTRACK"}},
		// accept traffic from 169.254.2.1:10261
		{iptables.Prepend, iptables.TableFilter, iptables.ChainOutput, []string{"-p", "tcp", "--sport", ifPort, "-s", ifIP, "-j", "ACCEPT"}},
		// skip connection track for traffic from container to localhost:10261
		{iptables.Prepend, iptables.Table("raw"), iptables.ChainPrerouting, []string{"-p", "tcp", "--dport", ifPort, "--destination", loopbackAddr, "-j", "NOTRACK"}},
		// skip connection track for traffic from host network to localhost:10261
		{iptables.Prepend, iptables.Table("raw"), iptables.ChainOutput, []string{"-p", "tcp", "--dport", ifPort, "--destination", loopbackAddr, "-j", "NOTRACK"}},
		// accept traffic to localhost:10261
		{iptables.Prepend, iptables.TableFilter, iptables.ChainInput, []string{"-p", "tcp", "--dport", ifPort, "--destination", loopbackAddr, "-j", "ACCEPT"}},
		// skip connection track for traffic from localhost:10261
		{iptables.Prepend, iptables.Table("raw"), iptables.ChainOutput, []string{"-p", "tcp", "--sport", ifPort, "-s", loopbackAddr, "-j", "NOTRACK"}},
		// accept traffic from localhost:10261
		{iptables.Prepend, iptables.TableFilter, iptables.ChainOutput, []string{"-p", "tcp", "--sport", ifPort, "-s", loopbackAddr, "-j", "ACCEPT"}},
	}
}

func (im *IptablesManager) EnsureIptablesRules() error {
	for _, rule := range im.rules {
		_, err := im.iptables.EnsureRule(rule.pos, rule.table, rule.chain, rule.args...)
		if err != nil {
			klog.Errorf("could not ensure iptables rule(%s -t %s %s %s), %v", rule.pos, rule.table, rule.chain, strings.Join(rule.args, ","), err)
			return err
		}
	}
	return nil
}
