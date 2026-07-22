# base-servers money demo, recorded with vhs (https://github.com/charmbracelet/vhs).
# Prereqs: the stack is up and the three secrets are exported (same values as the
# compose stack), then run:  vhs docs/demo.tape
Output "docs/demo.gif"
Set Shell "bash"
Set FontSize 16
Set Width 1120
Set Height 760
Set Padding 18
Sleep 800ms
Type "./scripts/demo.sh"
Enter
Sleep 11s
