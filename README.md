# checkAMS
A C program to verify that the certificates in MQ AMS configuration are in a RACF keyring.

## Overview of program
With AMS you specify the Distinquished Names(DN) of users who are allowed to sign or encrypt MQ messages.  The certificates for these DN's need to be in the xxxxAMSM's drq.ams.keyring.  If they are not present, or have problems, such as they are not valid, the messages from AMS are not very helpful.  The messages are as helpful as "one of the DN's in the configuration has a problem but I am not telling you which DN it was, nor what the problem was".

CheckAMS has two parts:
1. Provide a useful list of information in the keyring
1. Takes the output of the AMS dspmqspl command, and checks the DN's are in the keystore

### Provide a useful list of the contents of a keyring.
With the RACDCERT commands you can list the contents of a keyring, for example owner and label; and you can display details about a certificate, such as the DN of the subject, and the Certificate Authority, but you you cannot issue one command to display all the important information, nor ask, "is the DN for this issuer in the keystore".

Example output from checkAMS, listing certificates in keyring:
```
Subject CN=SSCARSA1024,OU=CA,O=SSS,C=GB                                                         
Issuer  CN=SSCARSA1024,OU=CA,O=SSS,C=GB                                                         
Self signed                                                                                     
Valid date range 21/02/13 12:32:33 to 24/02/13 12:32:33                                         
Owner irrcerta/LINUXCA                                                                          
Usage:Certauth Status:Trust                                                                     
                                                                                                           
Subject CN=colin,OU=longou,O=SSS                                                                
Issuer  CN=TEMP4Certification Authority,OU=TEST,O=TEMP                                          
Valid date range 21/03/25 00:00:00 to 22/03/25 23:59:59                                         
Owner COLIN/TEST                                                                                
Usage:Site Status:Trust      
```    
The first certificate is owned by irrcerta and has label LINUXA.   Userid irrcerta means it belongs to CERTAUTH.  The certificate is self signed, and has a long validity date.  It has a usage of CERTAUTH, and is trusted.

The second certificate belongs to userid COLIN, it has label TEST. It has a subject DN of Subject CN=colin,OU=longou,O=SSS, and was issued by CN=TEMP4Certification Authority,OU=TEST,O=TEMP.   It has a usage of Site, and is trusted.


### Check the AMS set up
The program takes as input the output of the dspmqspl -m... -export command, and checks the DN against certificates in the keyring.

Example output
```   
Userid START1, ring drq.ams.keyring                                                                                  
* Exported on Mon Mar 29 09:23:31 2021                                                                               
                                                                                                                      
dspmqspl -m CSQ9  -export                                                                                          
setmqspl -m CSQ9                                                                                                     
 -p AMSQ                                                                                                             
 -s SHA256                                                                                                           
 -a "CN=COLIN,O=SSS"                                                                                                 
   Owner COLIN/AMS Usage:Site Status:Trust Valid date range 21/03/21 00:00:00 to 22/03/21 18:45:00                  
 -a "O=aaaa, C=GB,CN=ja2"                                                                                            
 ! O=aaaa,C=GB,CN=ja2 Not found in key ring                                                                           
 -e AES256                                                                                                           
 -r "CN=COLIN,O=SSS"                                                                                                 
  Owner COLIN/AMS Usage:Site Status:Trust Valid date range 21/03/21 00:00:00 to 22/03/21 18:45:00                  
```   
   
This shows the keyring was START1/drq.ams.keyring.

It prints out the exported file, and for the -a and -r records, it adds information about the certificate, or reports if it is not found.

It reports that "CN=COLIN,O=SSS" was found, the certificate belongs to userid COLIN,label AMS, it has usage of Site, it is trusted, and has a valid date.

It also reports *O=aaaa,C=GB,CN=ja2 Not found in key ring*   This is because the definition in AMS has the wrong order.   The standard order is CN=ja2,O=aaaa,c=GB.  This certificate **is** in the keyring, but the program could not find it.  I could not see a way of converting bad format DNs to good DNs.

## Contents of package.
FTP the amscheck.xmit.bit to z/OS as binary.   Then use *TSO receive indsn(amscheck.xmit)* to create the load module in a PDS.

Upload  runamsch, ccasmch, asmcheck. and parmlist.h to a PDS.

Edit and submit runamsch.   It runs dspmqspl and puts the output into a temporary file.
The parm PARM='START1 drq.ams.keyring' is for userid START1 and the keyring drq.ams.keyring.   Your userid will need access to the userid's keyring. 

### if you want to compile the program
If you want to compile the program, you can edit ccasmch, and change the SYSIN, and where the header file is imported from.

