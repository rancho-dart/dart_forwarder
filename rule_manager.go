package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/coreos/go-iptables/iptables"
)

type IptablesRule struct {
	Table string
	Chain string
	Rule  []string
}

type RuleManager struct {
	ipt   *iptables.IPTables
	rules []IptablesRule
}

func NewRuleManager() *RuleManager {
	ipt, err := iptables.New()
	if err != nil {
		log.Fatalf("Failed to initialize iptables: %v", err)
	}
	return &RuleManager{
		ipt:   ipt,
		rules: []IptablesRule{},
	}
}

func (rm *RuleManager) AddRule(table, chain string, rule []string) error {
	exists, err := rm.ipt.Exists(table, chain, rule...)
	if err != nil {
		return fmt.Errorf("check exists: %v", err)
	}
	if !exists {
		if err := rm.ipt.Append(table, chain, rule...); err != nil {
			return fmt.Errorf("append rule: %v", err)
		}
		log.Printf("Rule added: %s %s %v", table, chain, rule)
		rm.rules = append(rm.rules, IptablesRule{table, chain, rule})
	} else {
		log.Printf("Rule already exists: %s %s %v", table, chain, rule)
	}
	return nil
}

func (rm *RuleManager) Cleanup() {
	log.Println("Cleaning up iptables rules...")
	for _, r := range rm.rules {
		if err := rm.ipt.Delete(r.Table, r.Chain, r.Rule...); err != nil {
			log.Printf("Failed to delete rule: %s %s %v, error: %v", r.Table, r.Chain, r.Rule, err)
		} else {
			log.Printf("Deleted rule: %s %s %v", r.Table, r.Chain, r.Rule)
		}
	}
}

func (rm *RuleManager) CleanupOnSignal() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c
	fmt.Println()
	rm.Cleanup()
	log.Println("Exit.")
	os.Exit(0)
}
