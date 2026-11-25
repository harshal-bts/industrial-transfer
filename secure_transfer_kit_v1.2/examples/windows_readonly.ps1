# Read-only inventory and SMB observations. Do not use as an authorization gate.
Get-Disk | Select-Object Number,FriendlyName,SerialNumber,UniqueId,BusType,IsBoot,IsSystem,HealthStatus,OperationalStatus
Get-Partition | Select-Object DiskNumber,PartitionNumber,DriveLetter,AccessPaths
Get-Volume | Select-Object DriveLetter,FileSystem,HealthStatus,Size,SizeRemaining,UniqueId
Get-SmbConnection | Select-Object ServerName,ShareName,Dialect,Signed,Encrypted
# A validated volume GUID can be queried by an authorized administrator:
# fsutil dirty query <validated-volume-guid>
# Never elevate the operator app, set dirty bits, repair, format or dismount.
