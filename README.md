# Simple Java Byte Code Parser

Python JVM that can only execute **`Hello, World`**

## Quickstart

```bash
# Compile a java hello world program
javac Hello.java

# Execute
python3 parse.py ./Hello.class
```

## Java Hello World
```java
public class Hello {
    public static void main(String args[]) {
        System.out.println("Hello from python JVM");
    }
}
```