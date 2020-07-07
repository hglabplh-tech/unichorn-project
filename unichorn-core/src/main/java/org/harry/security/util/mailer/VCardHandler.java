package org.harry.security.util.mailer;

import ezvcard.Ezvcard;
import ezvcard.VCard;
import ezvcard.parameter.EmailType;
import ezvcard.property.FormattedName;
import ezvcard.property.Nickname;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class VCardHandler {

    private static List<VCard> vcardList = new ArrayList<>();

    public static List<VCard> parseVCardXML(InputStream in) {
        try {
            vcardList = Ezvcard.parseXml(in).all();
            in.close();
            return vcardList;
        } catch (IOException e) {
            return null;
        }
    }

    public static void writeVCardXML(OutputStream out) {
        try {
            Ezvcard.writeXml(vcardList).go(out);
            out.flush();
            out.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void addVCard(String firstName, String lastName,
                                String nickName, String business,
                                String private1, String private2) {
        VCard newCard = new VCard();
        FormattedName fname = new FormattedName(firstName);
        FormattedName lname = new FormattedName(lastName);
        FormattedName nname = new FormattedName(nickName);
        newCard.addFormattedName(fname);
        newCard.addFormattedName(lname);
        newCard.addFormattedName(nname);
        newCard.addEmail(business, EmailType.WORK);
        newCard.addEmail(private1, EmailType.INTERNET);
        newCard.addEmail(private2, EmailType.HOME);
        vcardList.add(newCard);
    }

    public static Optional<VCard> findVCard(String firstName) {
        Optional<VCard> vcard = vcardList.stream().filter(e -> e.getFormattedNames().stream().anyMatch(t -> t.getValue().startsWith(firstName))).findFirst();
        return vcard;
    }

    public static List<VCard> getVcardList() {
        return vcardList;
    }
}
