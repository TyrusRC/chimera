// Headless IDC: finish auto-analysis and persist the database, then exit.
// Run by `idat -A -c -o<idb> -S build_idb.idc <binary>` to create a reusable IDB.
#include <idc.idc>
static main() {
  auto_wait();
  save_database();
  qexit(0);
}
