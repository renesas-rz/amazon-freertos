file_name = "src\silex\sx_src\sx_os_support\wifi_iface\interface\sx_netdev.c"

# open
with open(file_name) as f:
    data_lines = f.read()

# replace
data_lines = data_lines.replace("vDHCPProcess( pdTRUE );", "vDHCPProcess( pdTRUE,0 );")

# save
with open(file_name, mode="w") as f:
    f.write(data_lines)
