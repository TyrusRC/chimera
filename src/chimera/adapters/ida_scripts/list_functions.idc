// Headless IDC: dump every function as "addr<TAB>size<TAB>name" to the output
// path. __CHIMERA_OUT__ is substituted by the adapter (WSL cannot pass env vars
// to a Windows idat, so paths are baked into the script, not read from getenv).
#include <idc.idc>
static main() {
  auto f, ea, fend;
  auto_wait();
  f = fopen("__CHIMERA_OUT__", "w");
  if (f == 0) { qexit(3); }
  for (ea = get_next_func(0); ea != BADADDR; ea = get_next_func(ea)) {
    fend = get_func_attr(ea, FUNCATTR_END);
    fprintf(f, "%x\t%d\t%s\n", ea, (fend == BADADDR) ? 0 : fend - ea, get_func_name(ea));
  }
  fclose(f);
  qexit(0);
}
