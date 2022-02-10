# Verfeinerung des Angreifermodells und Fähigkeiten in einer Angriffspfadgenerierung

## Siehe auch
* forked from https://github.com/FluidTrust/Palladio-Addons-ContextConfidentiality-Analysis
* Meta-Modell: https://github.com/Patrick-Spiesberger/Palladio-Addons-ContextConfidentialityMetamodell_Mitigation
* Testmodelle: https://github.com/Patrick-Spiesberger/Testmodels

Dieses Projekt enthält eine Verfeinerung der oben genannten Analyse um den Aspekt der zusammengesetzten Komponenten, der Kontextauswahl und der Verschlüsselung. Konkret soll im Rahmen der Zugriffskontrolle ein Randfall betrachtet werden, welcher bisher eine potentielle Ausnutzung einer Schwachstelle gegebenenfalls nicht richtig identifizieren kann. Des Weiteren soll die Verschlüsselung von Daten in dem bestehenden Metamodell berücksichtigt und durch eine Erweiterung der Analyse ausgewertet werden. Eine Verschlüsselung von Daten bewirkt unter anderem, dass die Ausbreitung eines Angriffs gegebenenfalls frühzeitig unterbunden werden kann. Die Analyse soll außerdem um das in Palladio vorhandene Konstrukt der zusammengesetzten Komponenten erweitert werden. Diese Art von Komponenten ermöglicht die automatisierte Instanziierung mehrerer Teilkomponenten durch die Instanziierung der Hauptkomponenten. Alle drei Problematiken werden als Erweiterung des Palladio-Komponenten-Modells umgesetzt.

## Einführung

### Technologien
* Modellierung: 
	* Eclipse Modeling Framework ([EMF](https://www.eclipse.org/modeling/emf/ "EMF"))
* Code
	* Java 11
	* KAMP Framework 

## Installation

### Vorraussetzungen

* Java (getestet mit JDK 11.0.13)
* git (getestet mit Version 2.17.1)

### Schritt 1: Eclipse Modeling Tools
* Eclipse Modeling Tools Version [2021-09] installieren (https://www.eclipse.org/downloads/packages/release/2021-09/r/eclipse-modeling-tools "2021-09")
* Installieren Sie folgende Software über "Hilfe" -> "Neue Software installieren"
   * Palladio [Updatesite](https://updatesite.palladio-simulator.com/palladio-build-updatesite/releases/5.0.0/ "Updatesite")
   * KAMP [Updatesite](https://kamp-research.github.io/KAMP/)

### Schritt 2: Projekt importieren
* Klonen Sie dieses Repository
* In Eclipse:
	* Import -> General -> Existing Projects -> entpackten Ordner auswählen
	* Select All -> Import
	* Project -> Clean
	* Eclipse neustarten
	* Project -> Clean
