#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Zydis/Zydis.h>

static int hex_value(char value)
{
    if ((value >= '0') && (value <= '9'))
    {
        return value - '0';
    }
    if ((value >= 'a') && (value <= 'f'))
    {
        return value - 'a' + 10;
    }
    if ((value >= 'A') && (value <= 'F'))
    {
        return value - 'A' + 10;
    }
    return -1;
}

static size_t parse_bytes(const char* text, unsigned char* bytes, size_t capacity)
{
    size_t count = 0;
    int high = -1;
    for (; *text; ++text)
    {
        int value = hex_value(*text);
        if (value < 0)
        {
            continue;
        }
        if (high < 0)
        {
            high = value;
            continue;
        }
        if (count == capacity)
        {
            return capacity + 1;
        }
        bytes[count++] = (unsigned char)((high << 4) | value);
        high = -1;
    }
    return (high < 0) ? count : capacity + 1;
}

int main(int argc, char** argv)
{
    if (argc != 5)
    {
        fputs("Usage: oracle <real|compat> <intel|att> <address> <bytes>\n", stderr);
        return 2;
    }

    ZydisMachineMode mode;
    if (strcmp(argv[1], "real") == 0)
    {
        mode = ZYDIS_MACHINE_MODE_REAL_16;
    }
    else if (strcmp(argv[1], "compat") == 0)
    {
        mode = ZYDIS_MACHINE_MODE_LONG_COMPAT_16;
    }
    else
    {
        fputs("The machine mode is invalid.\n", stderr);
        return 2;
    }

    ZydisFormatterStyle style;
    if (strcmp(argv[2], "intel") == 0)
    {
        style = ZYDIS_FORMATTER_STYLE_INTEL;
    }
    else if (strcmp(argv[2], "att") == 0)
    {
        style = ZYDIS_FORMATTER_STYLE_ATT;
    }
    else
    {
        fputs("The syntax is invalid.\n", stderr);
        return 2;
    }

    char* end = NULL;
    ZyanU64 address = strtoull(argv[3], &end, 0);
    if (!end || *end)
    {
        fputs("The address is invalid.\n", stderr);
        return 2;
    }

    unsigned char bytes[64];
    size_t length = strcmp(argv[4], "-") == 0 ? 0 : parse_bytes(argv[4], bytes, sizeof(bytes));
    if (length > sizeof(bytes))
    {
        fputs("The byte string is invalid.\n", stderr);
        return 2;
    }

    ZydisDecoder decoder;
    ZydisFormatter formatter;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, mode, ZYDIS_STACK_WIDTH_16)) ||
        !ZYAN_SUCCESS(ZydisFormatterInit(&formatter, style)))
    {
        fputs("Oracle initialization failed.\n", stderr);
        return 2;
    }

    ZyanStatus status = ZydisDecoderDecodeFull(&decoder, bytes, length, &instruction, operands);
    if (!ZYAN_SUCCESS(status))
    {
        printf("error status=%08" PRIX32 "\n", (ZyanU32)status);
        return 0;
    }

    char text[256];
    status = ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
        instruction.operand_count_visible, text, sizeof(text), address, ZYAN_NULL);
    if (!ZYAN_SUCCESS(status))
    {
        printf("format-error status=%08" PRIX32 "\n", (ZyanU32)status);
        return 0;
    }

    printf("ok len=%u opw=%u adw=%u enc=%u mnemonic=%s text=%s",
        instruction.length, instruction.operand_width, instruction.address_width,
        instruction.encoding, ZydisMnemonicGetString(instruction.mnemonic), text);
    for (ZyanU8 index = 0; index < instruction.operand_count_visible; ++index)
    {
        printf(" op%u=%u:%u", index, operands[index].type, operands[index].size);
        if (operands[index].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            printf(":%s", ZydisRegisterGetString(operands[index].reg.value));
        }
        if ((operands[index].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) &&
            operands[index].imm.is_relative)
        {
            ZyanU64 target;
            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &operands[index], address,
                &target)))
            {
                printf(":target=%" PRIu64, target);
            }
        }
    }
    putchar('\n');
    return 0;
}
