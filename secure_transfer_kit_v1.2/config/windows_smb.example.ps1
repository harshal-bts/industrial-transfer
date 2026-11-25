# Infrastructure team example: review and adapt in dedicated lab only.
# Share Change access alone permits deletion: DO NOT release to users until
# granular NTFS ACLs and broker/immutable commit tests pass.
# New-SmbShare -Name IndustrialIncoming -Path D:\IndustrialIngestion\Incoming -ChangeAccess 'FACILITY\IndustrialTransferUsers' -EncryptData $true
# New-SmbShare -Name IndustrialReceipts -Path D:\IndustrialIngestion\Receipts -ReadAccess 'FACILITY\IndustrialTransferUsers' -EncryptData $true
# Set-SmbShare -Name IndustrialIncoming -EncryptData $true
Get-SmbShare | Select-Object Name,Path,EncryptData
