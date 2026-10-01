// Headless IDC: disassemble the function at __CHIMERA_ADDR__ to __CHIMERA_OUT__.
// Both placeholders are substituted by the adapter (no env vars on Windows idat).
#include <idc.idc>
static main() {
  auto f, ea, fend, a;
  auto_wait();
  f = fopen("__CHIMERA_OUT__", "w");
  if (f == 0) { qexit(3); }
  ea = __CHIMERA_ADDR__;
  fend = get_func_attr(ea, FUNCATTR_END);
  if (fend != BADADDR && fend > ea)
    for (a = ea; a != BADADDR && a < fend; a = next_head(a, fend))
      fprintf(f, "%x  %s\n", a, GetDisasm(a));
  fclose(f);
  qexit(0);
}
