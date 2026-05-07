package com.example;

public class Foo {
    public native int decrypt(byte[] data);

    private static String greet(String name) {
        return "hi " + name;
    }

    public void noop() {}

    public int sum(int a, int b) throws RuntimeException {
        return a + b;
    }

    public void log(String fmt, Object... args) {}
}
