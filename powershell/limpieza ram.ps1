[GC]::Collect()
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 255

# INDICAR LA RUTA EN DONDE TENEMOS RAMMAP
.\RAMMap
.\EmptyStandbyList.exe workingsets
.\EmptyStandbyList.exe modifiedpagelist
.\EmptyStandbyList.exe priority0standbylist
.\EmptyStandbyList.exe standbylist