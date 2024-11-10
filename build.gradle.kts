plugins {
    id("java")
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

group = "com.infosec"
version = "1.0-Release"
val projectName = "DMARCSecurity" // Set the project name here

repositories {
    mavenCentral()
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21)) // Set to Java 21
    }
}

dependencies {
    implementation("dnsjava:dnsjava:3.6.2") // DNS handling library
    compileOnly(files("/home/wolf/Desktop/BAPP/burpsuite_pro_v2024.9.4.jar")) // Path to Burp Suite JAR
}

tasks {
    shadowJar {
        archiveBaseName.set("SpoofProof")
        archiveVersion.set("1.0.1")
        archiveClassifier.set("")
    }
}




