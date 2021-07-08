# Generated by default/object.tt
package Paws::MediaConvert::AudioCodecSettings;
  use Moose;
  has AacSettings => (is => 'ro', isa => 'Paws::MediaConvert::AacSettings', request_name => 'aacSettings', traits => ['NameInRequest']);
  has Ac3Settings => (is => 'ro', isa => 'Paws::MediaConvert::Ac3Settings', request_name => 'ac3Settings', traits => ['NameInRequest']);
  has AiffSettings => (is => 'ro', isa => 'Paws::MediaConvert::AiffSettings', request_name => 'aiffSettings', traits => ['NameInRequest']);
  has Codec => (is => 'ro', isa => 'Str', request_name => 'codec', traits => ['NameInRequest']);
  has Eac3AtmosSettings => (is => 'ro', isa => 'Paws::MediaConvert::Eac3AtmosSettings', request_name => 'eac3AtmosSettings', traits => ['NameInRequest']);
  has Eac3Settings => (is => 'ro', isa => 'Paws::MediaConvert::Eac3Settings', request_name => 'eac3Settings', traits => ['NameInRequest']);
  has Mp2Settings => (is => 'ro', isa => 'Paws::MediaConvert::Mp2Settings', request_name => 'mp2Settings', traits => ['NameInRequest']);
  has Mp3Settings => (is => 'ro', isa => 'Paws::MediaConvert::Mp3Settings', request_name => 'mp3Settings', traits => ['NameInRequest']);
  has OpusSettings => (is => 'ro', isa => 'Paws::MediaConvert::OpusSettings', request_name => 'opusSettings', traits => ['NameInRequest']);
  has VorbisSettings => (is => 'ro', isa => 'Paws::MediaConvert::VorbisSettings', request_name => 'vorbisSettings', traits => ['NameInRequest']);
  has WavSettings => (is => 'ro', isa => 'Paws::MediaConvert::WavSettings', request_name => 'wavSettings', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::MediaConvert::AudioCodecSettings

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::MediaConvert::AudioCodecSettings object:

  $service_obj->Method(Att1 => { AacSettings => $value, ..., WavSettings => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::MediaConvert::AudioCodecSettings object:

  $result = $service_obj->Method(...);
  $result->Att1->AacSettings

=head1 DESCRIPTION

Settings related to audio encoding. The settings in this group vary
depending on the value that you choose for your audio codec.

=head1 ATTRIBUTES


=head2 AacSettings => L<Paws::MediaConvert::AacSettings>

Required when you set (Codec) under
(AudioDescriptions)E<gt>(CodecSettings) to the value AAC. The service
accepts one of two mutually exclusive groups of AAC settings--VBR and
CBR. To select one of these modes, set the value of Bitrate control
mode (rateControlMode) to "VBR" or "CBR". In VBR mode, you control the
audio quality with the setting VBR quality (vbrQuality). In CBR mode,
you use the setting Bitrate (bitrate). Defaults and valid values depend
on the rate control mode.


=head2 Ac3Settings => L<Paws::MediaConvert::Ac3Settings>

Required when you set (Codec) under
(AudioDescriptions)E<gt>(CodecSettings) to the value AC3.


=head2 AiffSettings => L<Paws::MediaConvert::AiffSettings>

Required when you set (Codec) under
(AudioDescriptions)E<gt>(CodecSettings) to the value AIFF.


=head2 Codec => Str

Choose the audio codec for this output. Note that the option Dolby
Digital passthrough (PASSTHROUGH) applies only to Dolby Digital and
Dolby Digital Plus audio inputs. Make sure that you choose a codec
that's supported with your output container:
https://docs.aws.amazon.com/mediaconvert/latest/ug/reference-codecs-containers.html#reference-codecs-containers-output-audio
For audio-only outputs, make sure that both your input audio codec and
your output audio codec are supported for audio-only workflows. For
more information, see:
https://docs.aws.amazon.com/mediaconvert/latest/ug/reference-codecs-containers-input.html#reference-codecs-containers-input-audio-only
and
https://docs.aws.amazon.com/mediaconvert/latest/ug/reference-codecs-containers.html#audio-only-output


=head2 Eac3AtmosSettings => L<Paws::MediaConvert::Eac3AtmosSettings>

Required when you set (Codec) under
(AudioDescriptions)E<gt>(CodecSettings) to the value EAC3_ATMOS.


=head2 Eac3Settings => L<Paws::MediaConvert::Eac3Settings>

Required when you set (Codec) under
(AudioDescriptions)E<gt>(CodecSettings) to the value EAC3.


=head2 Mp2Settings => L<Paws::MediaConvert::Mp2Settings>

Required when you set (Codec) under
(AudioDescriptions)E<gt>(CodecSettings) to the value MP2.


=head2 Mp3Settings => L<Paws::MediaConvert::Mp3Settings>

Required when you set Codec, under AudioDescriptionsE<gt>CodecSettings,
to the value MP3.


=head2 OpusSettings => L<Paws::MediaConvert::OpusSettings>

Required when you set Codec, under AudioDescriptionsE<gt>CodecSettings,
to the value OPUS.


=head2 VorbisSettings => L<Paws::MediaConvert::VorbisSettings>

Required when you set Codec, under AudioDescriptionsE<gt>CodecSettings,
to the value Vorbis.


=head2 WavSettings => L<Paws::MediaConvert::WavSettings>

Required when you set (Codec) under
(AudioDescriptions)E<gt>(CodecSettings) to the value WAV.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::MediaConvert>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

