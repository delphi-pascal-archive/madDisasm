object Form1: TForm1
  Left = 192
  Top = 120
  Width = 870
  Height = 640
  Caption = 'Form1'
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  OldCreateOrder = False
  OnCreate = FormCreate
  DesignSize = (
    854
    602)
  PixelsPerInch = 96
  TextHeight = 13
  object Memo1: TMemo
    Left = 8
    Top = 8
    Width = 841
    Height = 449
    Anchors = [akLeft, akTop, akRight, akBottom]
    ScrollBars = ssVertical
    TabOrder = 0
  end
  object LabeledEdit1: TLabeledEdit
    Left = 8
    Top = 480
    Width = 761
    Height = 21
    Anchors = [akLeft, akRight, akBottom]
    EditLabel.Width = 16
    EditLabel.Height = 13
    EditLabel.Caption = 'File'
    TabOrder = 1
  end
  object LabeledEdit2: TLabeledEdit
    Left = 8
    Top = 528
    Width = 121
    Height = 21
    Anchors = [akLeft, akRight, akBottom]
    EditLabel.Width = 44
    EditLabel.Height = 13
    EditLabel.Caption = 'FileOffset'
    TabOrder = 3
    OnChange = LabeledEdit2Change
  end
  object BitBtn1: TBitBtn
    Left = 776
    Top = 480
    Width = 75
    Height = 25
    Anchors = [akRight, akBottom]
    Caption = 'Browse'
    TabOrder = 2
    OnClick = BitBtn1Click
  end
  object BitBtn2: TBitBtn
    Left = 568
    Top = 568
    Width = 91
    Height = 25
    Anchors = [akRight, akBottom]
    Caption = 'DisasmFile'
    TabOrder = 4
    OnClick = BitBtn2Click
  end
  object BitBtn3: TBitBtn
    Left = 664
    Top = 568
    Width = 91
    Height = 25
    Anchors = [akRight, akBottom]
    Caption = 'DisAsm Func'
    TabOrder = 5
    OnClick = BitBtn3Click
  end
  object BitBtn4: TBitBtn
    Left = 760
    Top = 568
    Width = 91
    Height = 25
    Anchors = [akRight, akBottom]
    Caption = 'DisAsm DLL Func'
    TabOrder = 6
    OnClick = BitBtn4Click
  end
  object OpenDialog1: TOpenDialog
    Left = 272
    Top = 64
  end
end
