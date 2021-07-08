# Generated by default/object.tt
package Paws::Chime::Meeting;
  use Moose;
  has ExternalMeetingId => (is => 'ro', isa => 'Str');
  has MediaPlacement => (is => 'ro', isa => 'Paws::Chime::MediaPlacement');
  has MediaRegion => (is => 'ro', isa => 'Str');
  has MeetingId => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::Chime::Meeting

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Chime::Meeting object:

  $service_obj->Method(Att1 => { ExternalMeetingId => $value, ..., MeetingId => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Chime::Meeting object:

  $result = $service_obj->Method(...);
  $result->Att1->ExternalMeetingId

=head1 DESCRIPTION

A meeting created using the Amazon Chime SDK.

=head1 ATTRIBUTES


=head2 ExternalMeetingId => Str

The external meeting ID.


=head2 MediaPlacement => L<Paws::Chime::MediaPlacement>

The media placement for the meeting.


=head2 MediaRegion => Str

The Region in which you create the meeting. Available values:
C<af-south-1>, C<ap-northeast-1>, C<ap-northeast-2>, C<ap-south-1>,
C<ap-southeast-1>, C<ap-southeast-2>, C<ca-central-1>, C<eu-central-1>,
C<eu-north-1>, C<eu-south-1>, C<eu-west-1>, C<eu-west-2>, C<eu-west-3>,
C<sa-east-1>, C<us-east-1>, C<us-east-2>, C<us-west-1>, C<us-west-2>.


=head2 MeetingId => Str

The Amazon Chime SDK meeting ID.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Chime>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

