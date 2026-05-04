# ADReader
My own bloodhound viewer solution.

## To view the explanation, you can visit my post here:
https://medium.com/@byL0r3t/i-created-my-own-bloodhound-viewer-and-you-can-also-do-it-1f035f67da5b

## Output example:
CERTIFICATE SERVICE DCOM ACCESS: 0 hops -> CERTIFICATE SERVICE DCOM ACCESS                            
ALLOWED RODC PASSWORD REPLICATION GROUP: 0 hops -> ALLOWED RODC PASSWORD REPLICATION GROUP
DENIED RODC PASSWORD REPLICATION GROUP: 0 hops -> DENIED RODC PASSWORD REPLICATION GROUP
DC01.HACKSMARTER.LOCAL: 0 hops -> DC01.HACKSMARTER.LOCAL
ADMINISTRATORS: 1 hops -> CERTIFICATE SERVICE DCOM ACCESS --[Owns]--> ADMINISTRATORS
DOMAIN ADMINS: 1 hops -> CERTIFICATE SERVICE DCOM ACCESS --[GenericAll]--> DOMAIN ADMINS
ACCOUNT OPERATORS: 1 hops -> CERTIFICATE SERVICE DCOM ACCESS --[GenericAll]--> ACCOUNT OPERATORS
ENTERPRISE ADMINS: 1 hops -> CERTIFICATE SERVICE DCOM ACCESS --[GenericAll]--> ENTERPRISE ADMINS
Max hops: 1

CHAIN:
  ACCOUNT OPERATORS --[GenericAll]--> YORINOBU
  YORINOBU --[GenericWrite]--> SOULKILLER.SVC

CHAIN:
  ACCOUNT OPERATORS --[GenericAll]--> ALT.SVC
  ALT.SVC --[GenericAll]--> YORINOBU

CHAIN:
  ALT.SVC --[GenericAll]--> YORINOBU
  YORINOBU --[GenericWrite]--> SOULKILLER.SVC

### There is still some work to do, such as:
- Testing
- Graphical interface
- Implementation of AzureHound and RoadRecon