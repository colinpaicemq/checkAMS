// C header file for z/OS callable server IRRSDL00, and the results handle
//
//MIT License
//
//Copyright (c) 2021 Stromness Software Solutions.
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.
//
// This strucure is based on information from IBM.
//*
//* Contributors:
//*   Colin Paice - Initial Contribution
// it needs pragma pack to get the alignment right
//
// parm list for IRRSDL00 - access to key rings and certificates
//
 typedef  struct tagResultsHandle {
        int dbToken           ; //
        int Number_predicates ; //
        int Attribute_ID      ; //
        int Attribute_Length  ; //
        char * Attribute_ptr  ; //
     } ResultsHandle;
     ResultsHandle  resultsHandle;
 #pragma pack(1)
 struct {
    ResultsHandle * results_handle ; //  in 0
    int   certificate_usage ; //out 4
    int   isDefault         ; // out 8
    int   certificate_length; //in/out c
    char  * certificate    ; // in 10
    int   private_key_length; //in/out 14
    char  * private_key    ; //in 18
    int   private_key_type  ; //out 1c
    int   private_bitsize   ; //out 20
    int   label_length      ; //in/out 24
    char  * label           ; //in 28
    char  cert_useridl      ; // output     2c
    char  cert_userid[8]    ; // output     2d
    char  temp[3]            ; //
    int   subjects_dn_length ; //in 38
    char  * subjects_dn_ptr  ; //in 3c
    int   record_length      ; //in/out  40
    char  *  record_ptr      ; //inp 44
    int   cert_status        ; //in/out 48
 } parmlist;
 #pragma pack(4)
 //
