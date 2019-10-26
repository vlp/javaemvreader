/*
 * Copyright 2010 sasc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sasc.emv;

import sasc.iso7816.SmartCardException;
import java.util.Arrays;
import sasc.iso7816.Iso7816Commands;
import sasc.util.Util;

/**
 * Static utility methods used to construct EMV commands
 *
 * A complete list of all EMV commands (including standard ISO7816-4 commands):
 *
 * cls  ins  command
 * '8x' '1E' APPLICATION BLOCK
 * '8x' '18' APPLICATION UNBLOCK
 * '8x' '16' CARD BLOCK
 * '0x' '82' EXTERNAL AUTHENTICATE
 * '8x' 'AE' GENERATE APPLICATION CRYPTOGRAM
 * '0x' '84' GET CHALLENGE
 * '8x' 'CA' GET DATA (ATC, Last Online ATC, PIN Try Counter, LogFormat)
 * '8x' 'A8' GET PROCESSING OPTIONS
 * '0x' '88' INTERNAL AUTHENTICATE
 * '8x' '24' PERSONAL IDENTIFICATION NUMBER (PIN) CHANGE/UNBLOCK
 * '0x' 'B2' READ RECORD
 * '0x' 'A4' SELECT
 * '0x' '20' VERIFY //PIN
 * '8x' 'Dx' RFU for the payment systems
 * '8x' 'Ex' RFU for the payment systems
 * '9x' 'xx' RFU for manufacturers for proprietary INS coding
 * 'Ex' 'xx' RFU for issuers for proprietary INS coding
 *
 * EMV Book 3 : When required in a command message, Le shall always be set to '00'
 *
 * @author sasc
 */
public class EMVAPDUCommands {

    public static byte[] selectPSE() {
        return selectByDFName(Util.fromHexString("31 50 41 59 2E 53 59 53 2E 44 44 46 30 31")); //1PAY.SYS.DDF01
    }

    public static byte[] selectPPSE() {
        return selectByDFName(Util.fromHexString("32 50 41 59 2E 53 59 53 2E 44 44 46 30 31")); //2PAY.SYS.DDF01
    }

    public static byte[] selectByDFName(byte[] fileBytes) {
        return Iso7816Commands.selectByDFName(fileBytes, true, (byte)0x00);
    }

    public static byte[] selectByDFNameNextOccurrence(byte[] fileBytes) {
        return Iso7816Commands.selectByDFNameNextOccurrence(fileBytes, true, (byte)0x00);
    }

    public static byte[] readRecord(int recordNum, int sfi) {
        return Iso7816Commands.readRecord(recordNum, sfi);
    }

    /*
     *
     * Case 4s C-APDU
     */
    public static byte[] getProcessingOpts(DOL pdol, EMVApplication app) {
        String command;
        if (pdol != null && pdol.getTagAndLengthList().size() > 0) {
            byte[] pdolResponseData = EMVTerminal.constructDOLResponse(pdol, app);
            command = "80 A8 00 00";
            command += " " + Util.int2Hex(pdolResponseData.length + 2) + " 83 " + Util.int2Hex(pdolResponseData.length);
            command += " " + Util.prettyPrintHexNoWrap(pdolResponseData);
            command += " 00"; // Le
        } else {
            command = "80 A8 00 00 02 83 00 00"; //Last 00 is Le
        }
        return Util.fromHexString(command);
    }

    public static byte[] getApplicationTransactionCounter() {
        return Util.fromHexString("80 CA 9F 36 00");
    }

    public static byte[] getLastOnlineATCRegister() {
        return Util.fromHexString("80 CA 9F 13 00");
    }

    public static byte[] getPINTryConter() {
        return Util.fromHexString("80 CA 9F 17 00");
    }

    /*
     * Case 2 C-APDU
     */
    public static byte[] getLogFormat() {
        return Util.fromHexString("80 CA 9F 4F 00");
    }

    public static byte[] getData(byte p1, byte p2){
		return Util.fromHexString("80 CA "+Util.byte2Hex(p1) + " " + Util.byte2Hex(p2) + " 00");
	}

    public static byte[] internalAuthenticate(byte[] authenticationRelatedData) {
        return Iso7816Commands.internalAuthenticate(authenticationRelatedData);
    }

    public static byte[] externalAuthenticate(byte[] cryptogram, byte[] proprietaryBytes) {
        return Iso7816Commands.externalAuthenticate(cryptogram, proprietaryBytes);
    }

    /**
     *
     * Case 4s C-APDU
     *
     * @param referenceControlParameterP1
     * @param transactionRelatedData
     * @return
     */
    public static byte[] generateAC(byte referenceControlParameterP1, byte[] transactionRelatedData) {
        if(transactionRelatedData == null) {
            throw new IllegalArgumentException("Param 'transactionRelatedData' cannot be null");
        }
        byte[] cmd = new byte[5+transactionRelatedData.length+1];
        cmd[0] = (byte)0x80;
        cmd[1] = (byte)0xAE;
        cmd[2] = referenceControlParameterP1;
        cmd[3] = 0x00;
        cmd[4] = (byte)transactionRelatedData.length;
        System.arraycopy(transactionRelatedData, 0, cmd, 5, transactionRelatedData.length);
        cmd[cmd.length-1] = 0x00; //Le
        return cmd;
    }

    /**
     * The GET CHALLENGE command is used to obtain an unpredictable number from
     * the ICC for use in a security-related procedure.
     * The challenge shall be valid only for the next issued command
     *
     * The data field of the response message contains an 8-byte unpredictable number generated by the ICC
     *
     * @return String the APDU command GET CHALLENGE
     */
    public static byte[] getChallenge() {
        return Util.fromHexString("00 84 00 00 00");
    }

    /**
     * The VERIFY command is used for OFFLINE authentication.
     * The Transaction PIN Data (input) is compared with the Reference PIN Data
     * stored in the application (ICC).
     *
     * NOTE: The EMV command "Offline PIN" (plaintext) is vulnerable to a Man-in-the-middle attack.
     * Terminals should request online pin verification instead (or encipher PIN) !!
     *
     * Case 3 C-APDU
     *
     * @param p2Qualifier reference data qualifier
     * @param pinData PIN data (plain or enciphered to be sent)
     * @return
     */
    public static byte[] verifyPIN(byte p2Qualifier, byte[] pinData) {
    	if((pinData==null)||(pinData.length<8)) {
    		throw new IllegalArgumentException("Invalid PIN data for VERIFY");
    	}
        byte[] cmd = new byte[5+pinData.length];
        cmd[0] = 0x00;
        cmd[1] = 0x20;
        cmd[2] = 0x00;
        cmd[3] = p2Qualifier;
        cmd[4] = (byte)pinData.length; //Lc
        System.arraycopy(pinData, 0, cmd, 5, pinData.length);

        return cmd;
    }

    public static void main(String[] args) {
        System.out.println(Util.prettyPrintHexNoWrap(verifyPIN((byte)0x80, EMVUtil.makeFormat2PinBlock(new char[]{'1','2','3','4'}))));
    }
}
