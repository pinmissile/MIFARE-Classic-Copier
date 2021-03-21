# MIFARE Classic Copier
An Arduino Nano-based hardware proof-of-concept that can copy MIFARE Classic cards, given that they use factory default encryption keys, which is unfortunately more common than you'd think.

I do not condone any illegal usage of this project. Please behave, and be excellent to each other.

## Components
* Arduino Nano
* MFRC522 Module
* Blue LED
* Yellow LED

Additionally, if you want it to be portable:
* Battery pack (4.5 V works fine, 5 V is ideal)
* 330 Ω resistor
* Red LED (Power indicator)
* Power switch

## Schematic
![Image](https://github.com/pinmissile/MIFARE-Classic-Copier/blob/master/Schematic.jpg?raw=true)

## Dependencies
The [MFRC522](https://github.com/miguelbalboa/rfid) library, available from the Arduino IDE.

## Finished product
![Image](https://github.com/pinmissile/MIFARE-Classic-Copier/blob/master/Image.jpg?raw=true)

Snug little thing, I threw it together with a battery pack, some screws, a multipurpose electronics casing and some black bathroom silicon.

## Usage
The device has two modes: Read and Write. Upon powering up, the device will enter Read mode. Simply hold the reader up to the card you wish to clone.

The yellow light will activate, indicating authentication attempts and read operation. Don't remove the card from the reader while the yellow light is on.

If it manages to find the key and copy the contents of the card to RAM, the yellow light will turn off and the blue light will blink. The copier is now in write mode.

Hold the copier up to a blank card and wait for the yellow light to deactivate again. If the write operation was successful, the blue light will blink again. You have now successfully copied a card.
