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
    compileOnly("net.portswigger.burp.extender:burp-extender-api:2.3")
}

tasks {
    shadowJar {
        archiveBaseName.set("SpoofProof")
        archiveVersion.set("1.0.3")
        archiveClassifier.set("")
    }
}




