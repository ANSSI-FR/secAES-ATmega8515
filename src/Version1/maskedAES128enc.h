/*! \fn void asm_maskedAES128enc()
    \brief	process AES128 in encryption mode
    \param the inputs message, key and mask are 
           assumed to be stored in global variables
           input, key and mask respectively.
    \param the output is directly stored in the global
           variable input     
*/
void asm_maskedAES128enc();
