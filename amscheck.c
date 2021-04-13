 /**************************************************************
 MIT License
 Copyright (c) 2021 Stromness Software Solutions.
 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
 * Contributors:
 *   Colin Paice - Initial Contribution
 ************************************************************/
  // user needs access to the keyring eg
  // permit IRR.RUSERMAP class(FACILITY) access(READ) ID(ADCDA)
  // SETROPTS RACLIST(facility          ) REFRESH
  #pragma linkage(IRRSDL00 ,OS)
  #line 26
  #pragma runopts(POSIX(ON))
  /*Include standard libraries */
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>
  #include <stdarg.h>
  #include <iconv.h>
  #include <gskcms.h>

  void printInfo();
  void printCertInfo();
  void  displayCode(long SAF_RC,long RACF_RC,long RACF_RS);
  #include <parmlist.h>
  // we have a linked list of entries from the keyring
  //  we need to build this as the search capability does
  // not always work
  typedef struct tagLL       * pLL        ;
  typedef struct tagLL       {
          pLL   Next; /* linked list next pointer  */
          char * owner  ;
          char * subject;
          char * issuer;
          char * status;
          char * dates;
  } LL ;
  pLL pLLHead = 0;
  pLL pLLTemp = 0;
  //  These are used to hold data while building the cert data
  char  owner[130];
  char  subject[130];
  char  issuer[130];
  char  status[130];
  char  dates[130];
  char * pFuture ;
  //  This does the work
  void readKeyring(char * pUserid, char * pRing);
  //  get a date 30 days from now
  void  getFuture();
  // remove embedded blanks from the ams DN
  void  DNtoDN(char *);
  FILE * fCerts;
  char  DNNew[200]; // used when removing blanks from DN
  char * pDNNew = & DNNew[0];
int main( int argc, char *argv??(??))
{
   char * pUserid;
   char * pRingName;
   if (argc < 3)
   {
     printf("Program needs userid ring_name\n");
    return 8;
   }
   pUserid   = argv[1];
   pRingName = argv[2];
   printf("Userid %s, ring %s\n",pUserid,pRingName);
   char * pDN;

   FILE * SYSIN;
   char buffer[200];  // read the file
   int numRead;
   // main processing
   getFuture();  // set date 30 days in advance
   // we list all of the certicate information in dd:CERTS
   fCerts= fopen("dd:CERTS ", "w ");
   if (fCerts== 0)
   {
      perror("fopen CERTS ");
   }
   // read keyring and return linked list
   readKeyring(pUserid,pRingName);

   //  File has records from ams export
   SYSIN = fopen("dd:SYSIN ", "rb,type=record");
   if (SYSIN == 0)
   {
      perror("fopen SYSIN: ");
      return;
   }
   // read the file till the end
   while ( 1 ) {
     numRead = fread(&buffer, 1, sizeof(buffer), SYSIN);
     // if end of file then leave
     if (numRead == 0 ) break;
     buffer[numRead]=0; // set trailing null
     printf("%s \n", buffer);
     // only process -a and -r statements
     if ( memcmp(buffer+1,"-a",2) == 0)
        pDN = & buffer[5];
     else if ( memcmp(buffer+1,"-r",2) == 0)
        pDN = & buffer[5];
     else continue ;  // process next record

     // strip trailing blanks and training "
     // by moving from the right hand end to the left until
     // non blank and non quote
     // replace the blank or quote with null
     int i;
     for (i= strlen(pDN)-1 ; i > 2 ;i--)
     {
        if (pDN[i] == ' ') pDN[i]  = 0;
        else
        if (pDN[i] == '"') pDN[i]  = 0;
        else
          break;
     }
    // DN can be in the wrong format -eg with spaces CN=A, O=SSS
    // DNtoDN takes the string converts to X509 and back to DNNew
    DNtoDN(pDN);

    // loop around and print any matches
    int found = 0;
    // we have linked list starting with pLLHead and last one has
    // next = 0;
    for ( pLLTemp = pLLHead; pLLTemp != 0;pLLTemp = pLLTemp-> Next){
      // if names do not match, try the next one
      if (strcmp(pLLTemp-> subject,pDNNew) != 0) continue;
      found ++;
      // if we have mangled the DN then print it out
      // if the AMS name does not match the squashed name say so
      if (strcmp(pDN,pDNNew)!= 0)
         printf("    %s\n",  pDNNew);
      // print out key information from the certificate
      printf("    %s %s %s \n",
         pLLTemp -> owner,
         pLLTemp -> status,
         pLLTemp -> dates);
    }  // end of certificate linked list
    if (found == 0 )
       printf("! %s Not found in key ring \n",pDNNew);
    if (found >1   )
       printf("! Warning %s Multipled certificate with the same DN\n");
   }
   return 0;
}
 //////
 //
 // Print information about the certificate; eg  who owns it
 //
 //////
 void  printInfo()
 {
   int l;
   l = parmlist.cert_useridl;  // length of the userid that owns it
   sprintf(&owner[0],"Owner %*.*s/%*.*s\0",
   l,l,parmlist.cert_userid,
      parmlist.label_length,
      parmlist.label_length,
      parmlist.label); //  name of the certificate
   fprintf(fCerts,"    %s\n",owner);

   char * pUsage = "";
   switch(parmlist.certificate_usage)
   {
     case 2: pUsage = "Certauth" ;
       break;
     case 8: pUsage = "Personal" ;
       break;
     case 0: pUsage = "Site" ;
       break;
     default:
         pUsage =   "Unknown";
  }
  //  status
  char * pS;
  switch(parmlist.cert_status      )
  {
    case 0x80000000:pS=   "Trust" ;
      break;
    case 0x40000000:pS=   "High trust" ;
      break;
    case 0x20000000:pS=   "NO_trust" ;
      break;
    case 0x00000000:pS =  "Any" ;
      break;
    default        :pS =  "Unknown";
  }
  //  put out a warning of NO trust
  if ( parmlist.cert_status == 0x20000000)
  {
    printf("WARNING - %s certificate has NO trust %s\n",
    owner, subject);
  }
  // create the buffer for the linked list
  sprintf(&status[0],"Usage:%s Status:%s\0", pUsage,pS);
  // and print out the info
  fprintf(fCerts,"    %s\n",status);

  // the key size is usually 0 for the AMS keyrings
  // this is because the private keys are not visible
  // either because not sent, or have "site" or "certauth"
  //
  if ( parmlist.private_bitsize > 0)
  {
    char * pType;
    switch(parmlist.private_key_type)
     {
       case 0x00:  pType= "Not provided                    "; break;
       case 0x01:  pType= "PKCS #1 private key, DER encoded"; break;
       case 0x02:  pType= "ICSF key token label";  break;
       case 0x03:  pType= "PCICC key token label";
       case 0x04:  pType= "DSA private key, DER encoded";  break;
       case 0x06:
          pType= "Diffie-Hellman (DH) private key, DER encoded";
          break;
       case 0x07:  pType= "ECC private key, DER encoded"; break;
       case 0x09:  pType= "ECC key token label in the PKDS"; break;
       case 0x0b:  pType= "RSA key token label in the TKDS"; break;
       case 0x0c:  pType= "PCICC key token label";         ; break;
       case 0x0d:  pType= "ECC key token label in the TKDS"; break;
       case 0x0e:  pType= "DSA key token label in the TKDS"; break;
       default:
           pUsage =   "Unknown key type";
    }
    fprintf(fCerts,"    Key bit size %i key type %s\n",
                   parmlist.private_bitsize, pType);
 }
 }
 /////
 //
 //  Print out information from the certificate internals
 //
 /////
void printCertInfo()
{
  // format the certificate
  // convert to from record to a structure using decode...
  gsk_status gskrc;
  gsk_buffer cert;
  cert.length=   parmlist.certificate_length;
  cert.data  =   parmlist.certificate;
  x509_certificate x509;
  gskrc = gsk_decode_certificate(&cert, &x509);
  if (gskrc != 0) printf("gsk_decode_cert failed  %s\n",
       gsk_strerror(gskrc));

  // extract the subject, create record for Linked list and print it
  char * pName;
  pName   = "Unknown";
  gskrc =  gsk_name_to_dn (
             & x509.tbsCertificate.subject,
             &pName);
  if (gskrc != 0)
     printf("Subject gsk_name_to_dn  %s",  gsk_strerror(gskrc));
  sprintf(&subject[0],"%s\0",pName);
  fprintf(fCerts,"    Subject %s\n",&subject[0]);
  gsk_free_string(pName);

  // extract the issuer, create record for Linked list and print it
  pName   = "Unknown";
  gskrc =  gsk_name_to_dn (
         & x509.tbsCertificate.issuer,
         &pName);
  if (gskrc != 0)
     printf("Issuer gsk_name_to_dn  %s",  gsk_strerror(gskrc));
  sprintf(&issuer[0],"%s\0",pName);
  fprintf(fCerts,"    Issuer  %s\n",issuer);
  gsk_free_string(pName);

  // check to see if it is self signed
  if (strcmp(issuer,subject) == 0)
  fprintf(fCerts,"    Self signed\n");

  // extract the not-before, and not-after dates
  char * b;
  char * a;
  gsk_time_format time_format ; // routine sets this to type of value
  gsk_format_time (
      & x509             .tbsCertificate.validity.notBefore,
      & time_format,
      &b        );
   gsk_format_time (
      & x509             .tbsCertificate.validity.notAfter,
      & time_format,
      &a           );
   // print warning  if has or soon will expire
   if (strcmp(a,pFuture) <= 0)
   printf("WARNING - %s certificate has/will expire "
                     "%2.2s/%2.2s/%2.2s %2.2s:%2.2s:%2.2s %s\n",
                      owner,
                      a,   a+2,  a+4,   a+6,  a+8,  a+10,
                      subject);
   sprintf(&dates[0],"Valid date range"
                     " %2.2s/%2.2s/%2.2s %2.2s:%2.2s:%2.2s "
                     "to %2.2s/%2.2s/%2.2s %2.2s:%2.2s:%2.2s\0",
                      b,   b+2,  b+4,   b+6,  b+8,  b+10,
                      a,   a+2,  a+4,   a+6,  a+8,  a+10);
   fprintf(fCerts,"    %s\n",dates);
   gsk_free_string(b);  // must free it once used

   gsk_free_string(a);  // must free it once used

   gsk_free_certificate(&x509);
return;
}
  /////
  //
  //  readKeyRing
  //   Read the kyering and generate linked list of certificates in ring
  //   Note: using search on DN did not always work, so implement linked
  //   list.  Also not sure if "no trust" certificates showed up with
  //   search.
  //
  /////
void readKeyring(char * pUserid, char * pRingName){
   // length of ...
   int  lUserid;
   int  lRingName;
   lUserid = strlen(pUserid);
   lRingName = strlen(pRingName);
   char  requestType   = 0x01 ; /*Data getFirst  */
   struct {
              char length;
              char value[8];
            }  cert_userid;

   struct {
              char length;
              char value[8];
            }  RACF_userid;
   char * workarea ;
   workarea = (char *) malloc(1024)   ;
   if ( workarea == 0)
   {
      printf("Malloc failed\n");
      exit(8);
   }
   // IRRSDL00 parameters
   long ALET1= 0;
   long ALET2= 0;
   long ALET3= 0;
   long SAF_RC,RACF_RC,RACF_RS;
   int parmlist_version = 1;
   // these are used for IRRSDL00 to return values into
   // they should be plenty big enough
   char record[5000];
   char dn[500] ;
   char  label[32]      ;
   char certificate[2000];
   char    key[5000]       ;
   struct {
            char length;
            char value[247];
          }  ring_name;
   // first time, set this ... routine updates it
   resultsHandle.dbToken = 0;
   // we are not using search capabilities on DN - it doesnt always
   // work, so set number of search items to 0
   resultsHandle.Number_predicates  = 0;
   // set up ring name
   if (lRingName > sizeof(ring_name.value))
       lRingName =  sizeof(ring_name.value);
   memcpy(ring_name.value,pRingName,lRingName);
   ring_name.length=lRingName;

   // Basic checks

   if (lUserid > sizeof(RACF_userid.value))
       lUserid = sizeof(RACF_userid.value) ;
   memcpy(RACF_userid.value,pUserid, lUserid);
   RACF_userid.length = lUserid;

   resultsHandle.Attribute_ID       = 0;
   while ( 1 ) {
     // reset this
     cert_userid.length = 8;  // how big the buffer is

     SAF_RC=15;  // preset this
 //  next two lines show how to search - but doesnt work
 //  resultsHandle.Attribute_Length   = derDN.length ;
 //  resultsHandle.Attribute_ptr      = derDN.data          ;

     parmlist.results_handle = &         resultsHandle;
 // We need storage for parameters - just allocate some large amounts
     parmlist.certificate_length  = sizeof(certificate);
     parmlist.certificate         =( char *)  &certificate;

     // reset the lengths as irrsld00 resets them to size used
     parmlist.private_key_length = sizeof(key);
     parmlist.private_key         =(char *) &key        ;

     parmlist.label_length       = sizeof(label);
     parmlist.label               =(char *) &label      ;

     parmlist.subjects_dn_length = sizeof(dn);
     parmlist.subjects_dn_ptr     =(char *) &dn         ;

     parmlist.record_length = sizeof(record);
     parmlist.record_ptr          = (char *)&record     ;

     // reset this each time
     parmlist.cert_useridl=  sizeof(parmlist.cert_userid); // 8

     int attributes   =          0;
     // getfirst or getnext
     IRRSDL00( workarea, // WORKAREA
                  &ALET1  , // ALET
                  &SAF_RC, // SAF RC
                  &ALET2, // ALET
                  &RACF_RC,// RACF RC
                  &ALET3 , // ALET
                  &RACF_RS,// RACF Reason

                  &requestType ,// function code
                  &attributes,  // option search for ...
                  &RACF_userid, // RACF userid
                  &ring_name, // certificate fw ...  cert
                  &parmlist_version,
                  (char * ) & parmlist );
     if (SAF_RC > 0)
     {
       if ( RACF_RS  != 44 ) // not found
         displayCode(SAF_RC,RACF_RC,RACF_RS);
       break;
     }
     // process the data
     // print it out and return strings with the data

     printCertInfo();
     printInfo();

     // Build the linked list of the data
     // allocate storage,
     pLLTemp = malloc(sizeof(LL));
     // chain it in
     pLLTemp-> Next = pLLHead;
     pLLHead = pLLTemp;
     // fill in the data, copying it from the temp variables
     pLLTemp -> owner  = strdup(owner );
     pLLTemp -> issuer = strdup(issuer);
     pLLTemp -> subject= strdup(subject);
     pLLTemp -> dates  = strdup(dates);
     pLLTemp -> status = strdup(status);
     fprintf(fCerts," \n");
  #ifdef doesnt_work
     // you are meant to do a dataabortquery after each request
     // but it does not work
     // the following section fails becaue
     // resultsHandle.dbToken is set to 0 and you get
     //   return code SAF 8 RACF 8 RS 36
     // free the resources by the DataAbortQuery command
     requestType   = 0x03;  // DataAbortQuery
     IRRSDL00( workarea, // WORKAREA
                  &ALET1  , // ALET
                  &SAF_RC, // SAF RC
                  &ALET2, // ALET
                  &RACF_RC,// RACF RC
                  &ALET3 , // ALET
                  &RACF_RS,// RACF Reason

                  &requestType ,// function code
                  &attributes,  // option
                  &RACF_userid, // RACF userid
                  &ring_name, // certificate fw ...  cert
                  &parmlist_version,   // Aplication userid
                  aparmlist );
     if (SAF_RC > 0)
     {
       printf("  Data abort return code SAF %d RACF %d RS %d\n",
        SAF_RC,RACF_RC,RACF_RS  );
       break;
     }
  #endif
     requestType   = 0x02;  // second and later use get next
    }  // while loop
   return;
}
 /////
 //
 // getFuture
 //    Routing to get a date 30 days from now and format it
 //
 /////
void getFuture(){
   /* get a time 30 days from now */
   time_t t1;
   struct tm *t2;
   t1 = time(NULL);
   t2 = localtime(&t1);
   t2 -> tm_mday += 30;  // 30 days from now
   gsk_time_format time_format = 0;
   gsk_format_time (
         t2 ,
       & time_format,
       &pFuture  );
}
 /////
 //
 // DNtoDN
 //   a DN can be badly formatted, eg with blanks, so take what
 //   we are given and convert to x509 and back, so removing blanks etc
 //
 /////
void DNtoDN(char * pDN)
{
  // remove trailing blanks and the "
  int i;
  for (i= strlen(pDN)-1 ; i > 2 ;i--)
  {
    if (pDN[i] == ' ') pDN[i]  = 0;
    else
    if (pDN[i] == '"') pDN[i]  = 0;
    else
      break;
   }
   gsk_status gskrc;
   x509_name  x509_name;
   // convert to x509 format
   gskrc =  gsk_dn_to_name (pDN,  &x509_name);
   if (gskrc != 0)
   {
     printf("gsk_dn_to_name failed %s. Input %s\n",
            gsk_strerror(gskrc),pDN);
     return    ;
   }
   // and back to DN format
   gskrc = gsk_name_to_dn(&x509_name,&pDNNew);
   if (gskrc != 0) printf("gsk_name_to_dn failed %s with %s\n",
     gsk_strerror(gskrc),&pDNNew);
   gsk_free_name(&x509_name);
   return    ;
}
void  displayCode(long SAF_RC,long RACF_RC,long RACF_RS)
{
 char buffer[50];
 char * pReason = "Unknown";
 if ( SAF_RC == 0 && RACF_RC == 0) return;
 if ( SAF_RC == 8 || RACF_RC == 8)
 switch (RACF_RS)
 {
   // common
   case   4 : pReason = "Parm list error ";
   break;
   case   8 : pReason = "Not RACF authorised";
   break;
   case  12 : pReason = "Internal error";
   break;
   case  16 : pReason = "Cannot establish recovery environment";
   break;
   case  20 : pReason = "Request not define";
   break;
   case  24 : pReason = "Parmlist version wrong";
   break;
   case  28 : pReason = "Ring_name length of RACF_userid length";
   break;
   //   get first, get next error
   case  32 : pReason = "Length error Record_id, label, Cert_user";
   break;
   case  36 : pReason = "dbToken error";
   break;
   case  40 : pReason = "Internal error";
   break;
   case  44 : pReason = "No certificate found - or end of list";
   break;
   case  48 : pReason = "An area was not long enough";
   break;
   case  52 : pReason = "Internal error - private key data ";
   break;
   case  56 : pReason = "Parameter error";
     break;
   case  80 : pReason = "Internal error PKCS#11";
     break;
   case  84 : pReason = "Keyring not found problem";
     break;
   default:
     sprintf(&buffer[0],"Reason code %d\n",RACF_RS);
     pReason = &buffer[0];
 }
   printf("  Return code SAF %d RACF %d RS %d %s\n",
        SAF_RC,RACF_RC,RACF_RS,pReason  );
}
