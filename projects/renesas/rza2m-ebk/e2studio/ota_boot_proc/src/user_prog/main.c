/***********************************************************************
*
*  FILE        : main.c
*  DATE        : 2020-03-19
*  DESCRIPTION : Main Program
*
*  NOTE:THIS IS A TYPICAL EXAMPLE.
*
***********************************************************************/
#include <stdio.h>
#include "r_typedefs.h"
#include "r_fwup_if.h"

int_t main( void )
{
    int32_t result_secure_boot;

    while(1)
    {
    	result_secure_boot = R_FWUP_SecureBoot();
		if (FWUP_SUCCESS == result_secure_boot)
		{
			R_FWUP_ExecuteFirmware();
			while(1); /* infinite loop */
		}
		else if (FWUP_FAIL == result_secure_boot)
		{
			while(1)
			{
				/* infinity loop */
			}
		}
		else if (FWUP_IN_PROGRESS == result_secure_boot)
		{
			continue;
		}
		else
		{
			while(1)
			{
				/* infinite loop */
			}
		}
    }

    return 0;
}
/* End of File */


