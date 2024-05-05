package main

import (
	"Findyou/common/db"
	"Findyou/common/loadyaml"
	"Findyou/common/workflow"
)

func main() {
	prepare()
	workflow.Workflowrun()
}

func prepare() {
	db.CheckAndCreate()
	loadyaml.Loadyaml()
}
