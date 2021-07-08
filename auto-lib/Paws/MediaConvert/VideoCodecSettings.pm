# Generated by default/object.tt
package Paws::MediaConvert::VideoCodecSettings;
  use Moose;
  has Av1Settings => (is => 'ro', isa => 'Paws::MediaConvert::Av1Settings', request_name => 'av1Settings', traits => ['NameInRequest']);
  has AvcIntraSettings => (is => 'ro', isa => 'Paws::MediaConvert::AvcIntraSettings', request_name => 'avcIntraSettings', traits => ['NameInRequest']);
  has Codec => (is => 'ro', isa => 'Str', request_name => 'codec', traits => ['NameInRequest']);
  has FrameCaptureSettings => (is => 'ro', isa => 'Paws::MediaConvert::FrameCaptureSettings', request_name => 'frameCaptureSettings', traits => ['NameInRequest']);
  has H264Settings => (is => 'ro', isa => 'Paws::MediaConvert::H264Settings', request_name => 'h264Settings', traits => ['NameInRequest']);
  has H265Settings => (is => 'ro', isa => 'Paws::MediaConvert::H265Settings', request_name => 'h265Settings', traits => ['NameInRequest']);
  has Mpeg2Settings => (is => 'ro', isa => 'Paws::MediaConvert::Mpeg2Settings', request_name => 'mpeg2Settings', traits => ['NameInRequest']);
  has ProresSettings => (is => 'ro', isa => 'Paws::MediaConvert::ProresSettings', request_name => 'proresSettings', traits => ['NameInRequest']);
  has Vc3Settings => (is => 'ro', isa => 'Paws::MediaConvert::Vc3Settings', request_name => 'vc3Settings', traits => ['NameInRequest']);
  has Vp8Settings => (is => 'ro', isa => 'Paws::MediaConvert::Vp8Settings', request_name => 'vp8Settings', traits => ['NameInRequest']);
  has Vp9Settings => (is => 'ro', isa => 'Paws::MediaConvert::Vp9Settings', request_name => 'vp9Settings', traits => ['NameInRequest']);
  has XavcSettings => (is => 'ro', isa => 'Paws::MediaConvert::XavcSettings', request_name => 'xavcSettings', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::MediaConvert::VideoCodecSettings

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::MediaConvert::VideoCodecSettings object:

  $service_obj->Method(Att1 => { Av1Settings => $value, ..., XavcSettings => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::MediaConvert::VideoCodecSettings object:

  $result = $service_obj->Method(...);
  $result->Att1->Av1Settings

=head1 DESCRIPTION

Video codec settings, (CodecSettings) under (VideoDescription),
contains the group of settings related to video encoding. The settings
in this group vary depending on the value that you choose for Video
codec (Codec). For each codec enum that you choose, define the
corresponding settings object. The following lists the codec enum,
settings object pairs. * AV1, Av1Settings * AVC_INTRA, AvcIntraSettings
* FRAME_CAPTURE, FrameCaptureSettings * H_264, H264Settings * H_265,
H265Settings * MPEG2, Mpeg2Settings * PRORES, ProresSettings * VC3,
Vc3Settings * VP8, Vp8Settings * VP9, Vp9Settings * XAVC, XavcSettings

=head1 ATTRIBUTES


=head2 Av1Settings => L<Paws::MediaConvert::Av1Settings>

Required when you set Codec, under VideoDescriptionE<gt>CodecSettings
to the value AV1.


=head2 AvcIntraSettings => L<Paws::MediaConvert::AvcIntraSettings>

Required when you choose AVC-Intra for your output video codec. For
more information about the AVC-Intra settings, see the relevant
specification. For detailed information about SD and HD in AVC-Intra,
see https://ieeexplore.ieee.org/document/7290936. For information about
4K/2K in AVC-Intra, see
https://pro-av.panasonic.net/en/avc-ultra/AVC-ULTRAoverview.pdf.


=head2 Codec => Str

Specifies the video codec. This must be equal to one of the enum values
defined by the object VideoCodec.


=head2 FrameCaptureSettings => L<Paws::MediaConvert::FrameCaptureSettings>

Required when you set (Codec) under
(VideoDescription)E<gt>(CodecSettings) to the value FRAME_CAPTURE.


=head2 H264Settings => L<Paws::MediaConvert::H264Settings>

Required when you set (Codec) under
(VideoDescription)E<gt>(CodecSettings) to the value H_264.


=head2 H265Settings => L<Paws::MediaConvert::H265Settings>

Settings for H265 codec


=head2 Mpeg2Settings => L<Paws::MediaConvert::Mpeg2Settings>

Required when you set (Codec) under
(VideoDescription)E<gt>(CodecSettings) to the value MPEG2.


=head2 ProresSettings => L<Paws::MediaConvert::ProresSettings>

Required when you set (Codec) under
(VideoDescription)E<gt>(CodecSettings) to the value PRORES.


=head2 Vc3Settings => L<Paws::MediaConvert::Vc3Settings>

Required when you set (Codec) under
(VideoDescription)E<gt>(CodecSettings) to the value VC3


=head2 Vp8Settings => L<Paws::MediaConvert::Vp8Settings>

Required when you set (Codec) under
(VideoDescription)E<gt>(CodecSettings) to the value VP8.


=head2 Vp9Settings => L<Paws::MediaConvert::Vp9Settings>

Required when you set (Codec) under
(VideoDescription)E<gt>(CodecSettings) to the value VP9.


=head2 XavcSettings => L<Paws::MediaConvert::XavcSettings>

Required when you set (Codec) under
(VideoDescription)E<gt>(CodecSettings) to the value XAVC.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::MediaConvert>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

