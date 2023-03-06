# Phishing Example
High level: Create a fake Job Application that is 'encrypted'. This should trick the victim into enabling content and therefore execute our payload.

Create a Word file with content like the following (you can also add a RSA Secured Logo in the header to improve the perception of legitimacy)

```
Job Application for Human Resources Assistant
---------------------------------------------
This file is encrypted with RSA to protect personal Information
To comply with GDPR regulations please enable Editing and enable content shown above

<!--RSA Encrypted Block --------------->
QSBwaGlzaGluZyBhdHRhY2sgZXhwbG9pdHMgYSB2aWN0aW0ncyBiZWhhdmlvciwgbGV2ZXJhZ2lu
ZyB0aGVpciBjdXJpb3NpdHkgb3IgZmVhciB0byBlbmNvdXJhZ2UgdGhlbSB0byBsYXVuY2ggb3Vy
IHBheWxvYWQgZGVzcGl0ZSB0aGVpciBiZXR0ZXIganVkZ2VtZW50LiBQb3B1bGFyIG1lY2hhbmlz
bXMgaW5jbHVkZSBqb2IgYXBwbGljYXRpb25zLCBoZWFsdGhjYXJlIGNvbnRyYWN0IHVwZGF0ZXMs
IGludm9pY2VzIG9yIGh1bWFuIHJlc291cmNlcyByZXF1ZXN0cywgZGVwZW5kaW5nIG9uIHRoZSB0
YXJnZXQgb3JnYW5pemF0aW9uIGFuZCBzcGVjaWZpYyBlbXBsb3llZXMu
....
<!--End of RSA Encryption ------------>

```
Make a copy of the Word file and delete existing content.
Next insert the 'decrypted' content. Example:

```
PERSONAL SUMMARY
An effective and confident communicator who is also ...


CAREER HISTORY
HR Assistant  -  May 2008 - Present

Responsible for ...

```
Mark all the text and navigate to Insert > Quick Parts > AutoTexts > Save Selection to Autotext Gallery
Name it 'TheDoc' for example.

Now delete the text and insert the 'encrypted' content.
Create a macro with the following content:

```
Sub Document_Open()
    SubstitutePage
End Sub

Sub AutoOpen()
    SubstitutePage
End Sub

Sub SubstitutePage()
    ActiveDocument.Content.Select
    Selection.Delete
    ActiveDocument.AttachedTemplate.AutoTextEntries("TheDoc").Insert Where:=Selection.Range, RichText:=True
End Sub
```

