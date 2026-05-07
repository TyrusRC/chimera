package com.example

class Bar {
    external fun nativeDecrypt(data: ByteArray): Int

    fun greet(name: String): String = "hi $name"

    @JvmStatic
    fun staticHelper() {}
}
