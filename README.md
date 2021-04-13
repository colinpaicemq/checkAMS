# checkAMS
C program to verify that the certificate in MQ AMS are in a racf keyring

## Overview of program
With AMS you specify the Distinquished names of users who are allowed to sign or encrypt MQ messages.  The certificates for these DN's need to be in the xxxxAMSM's drq.ams.keyring.  If they are not present, or have problems, such as they are not valid, the messages from AMS are not very helpful.  The messages are as helpful as "one of the DN's in the configuration has a problem but I am not telling you which DN it was, nor what the problem was".
CheckAMS has two parts
1. Provide a useful list of information in the keyring
1. Takes the output of the AMS dspmqspl command, and checks the DN's are in the keystore

### Provide a useful list of the contents of a keyring.
With the RACDCERT commands you can list the contents of a keyring, for example owner and label; and you can display details about a certificate, such as the DN of the subject, and the Certificate Authority, but you cannot ask, "is the DN for this issuer in the keystore".

Example output

    Subject CN=SSCARSA1024,OU=CA,O=SSS,C=GB                                                         
    Issuer  CN=SSCARSA1024,OU=CA,O=SSS,C=GB                                                         
    Self signed                                                                                     
    Valid date range 21/02/13 12:32:33 to 24/02/13 12:32:33                                         
    Owner irrcerta/LINUXCA                                                                          
    Usage:Certauth Status:Trust                                                                     
    _________                                                                                                           
    Subject CN=colin,OU=longou,O=SSS                                                                
    Issuer  CN=TEMP4Certification Authority,OU=TEST,O=TEMP                                          
    Valid date range 21/03/25 00:00:00 to 22/03/25 23:59:59                                         
    Owner COLIN/TEST                                                                                
    Usage:Site Status:Trust      
    
The first certificate is owner by irrcerta and has label LINUXA.   Userid irrcerta means it belongs to CERTAUTH.  The certificate is self signed, and has a long validity date.  It has a usage pf CERTAUTH, and is trusted.

The second certificate belongs to userid COLIN, it has label TEST. It has a subject DN of Subject CN=colin,OU=longou,O=SSS, and was issued by CN=TEMP4Certification Authority,OU=TEST,O=TEMP.   It has a usage of Site, and is trusted.

### Checks the AMS set up
The program takes as input the output of the dspmqspl -m... -export command, and checks the DN against certificates in the keyring.

example output
   
   Userid START1, ring drq.ams.keyring                                                                                  
   * Exported on Mon Mar 29 09:23:31 2021                                                                               
   __                                                                                                                       
   * dspmqspl -m CSQ9  -export                                                                                          
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
   -r "CN=ADCDB,O=SSS"    
   
This shows the keyring was START1/drq.ams.keyring.

It prints out the exported file, and for the -a and -r records, it adds information about the certificate, or reports if it is not found.

It reports that "CN=COLIN,O=SSS" was found, the certificate belongs to userid COLIN label AMS, it has usage of Site, it is trusted, and has a valid date.

It also reports *O=aaaa,C=GB,CN=ja2 Not found in key ring*   This is because the definition in AMS has the wrong order.   The standard order is CN=ja2,O=aaaa,c=GB.  This certificate **is** in the keystore, but the program could not find it.  I could not see a way of converting bad DNs to good DNs.
