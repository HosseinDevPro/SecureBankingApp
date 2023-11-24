package com.hkh.securebankingapp.utils

object HexUtils {

    private const val hex_chars = "0123456789ABCDEF"

    fun ByteArray.byteArrayToHex() : String {
        val hexChars = hex_chars.toCharArray()
        val result = StringBuffer()

        this.forEach {
            val octet = it.toInt()
            val firstIndex = (octet and 0xF0).ushr(4)
            val secondIndex = octet and 0x0F
            result.append(hexChars[firstIndex])
            result.append(hexChars[secondIndex])
        }

        return result.toString()
    }

    fun String.hexToByteArray() : ByteArray {
        val hexChars = hex_chars.toCharArray()
        val result = ByteArray(this.length / 2)

        for (i in 0 until this.length step 2) {
            val firstIndex = hexChars.indexOf(this[i]);
            val secondIndex = hexChars.indexOf(this[i + 1]);

            val octet = firstIndex.shl(4).or(secondIndex)
            result.set(i.shr(1), octet.toByte())
        }

        return result
    }

}