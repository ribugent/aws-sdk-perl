# Generated by default/object.tt
package Paws::MediaConnect::MediaStreamSourceConfigurationRequest;
  use Moose;
  has EncodingName => (is => 'ro', isa => 'Str', request_name => 'encodingName', traits => ['NameInRequest'], required => 1);
  has InputConfigurations => (is => 'ro', isa => 'ArrayRef[Paws::MediaConnect::InputConfigurationRequest]', request_name => 'inputConfigurations', traits => ['NameInRequest']);
  has MediaStreamName => (is => 'ro', isa => 'Str', request_name => 'mediaStreamName', traits => ['NameInRequest'], required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::MediaConnect::MediaStreamSourceConfigurationRequest

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::MediaConnect::MediaStreamSourceConfigurationRequest object:

  $service_obj->Method(Att1 => { EncodingName => $value, ..., MediaStreamName => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::MediaConnect::MediaStreamSourceConfigurationRequest object:

  $result = $service_obj->Method(...);
  $result->Att1->EncodingName

=head1 DESCRIPTION

The definition of a media stream that you want to associate with the
source.

=head1 ATTRIBUTES


=head2 B<REQUIRED> EncodingName => Str

The format you want to use to encode the data. For ancillary data
streams, set the encoding name to smpte291. For audio streams, set the
encoding name to pcm. For video, 2110 streams, set the encoding name to
raw. For video, JPEG XS streams, set the encoding name to jxsv.


=head2 InputConfigurations => ArrayRef[L<Paws::MediaConnect::InputConfigurationRequest>]

The transport parameters that you want to associate with the media
stream.


=head2 B<REQUIRED> MediaStreamName => Str

The name of the media stream.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::MediaConnect>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

