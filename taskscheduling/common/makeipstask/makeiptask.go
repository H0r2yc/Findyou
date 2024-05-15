package makeipstask

import "Findyou.TaskScheduling/common/db/mysqldb"

func makeipstack() {
	allips, _ := mysqldb.GetAllIPs("Waiting", true)
}
