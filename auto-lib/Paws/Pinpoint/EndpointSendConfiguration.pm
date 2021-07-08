# Generated by default/object.tt
package Paws::Pinpoint::EndpointSendConfiguration;
  use Moose;
  has BodyOverride => (is => 'ro', isa => 'Str');
  has Context => (is => 'ro', isa => 'Paws::Pinpoint::MapOf__string');
  has RawContent => (is => 'ro', isa => 'Str');
  has Substitutions => (is => 'ro', isa => 'Paws::Pinpoint::MapOfListOf__string');
  has TitleOverride => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::Pinpoint::EndpointSendConfiguration

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Pinpoint::EndpointSendConfiguration object:

  $service_obj->Method(Att1 => { BodyOverride => $value, ..., TitleOverride => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Pinpoint::EndpointSendConfiguration object:

  $result = $service_obj->Method(...);
  $result->Att1->BodyOverride

=head1 DESCRIPTION

Specifies the content, including message variables and attributes, to
use in a message that's sent directly to an endpoint.

=head1 ATTRIBUTES


=head2 BodyOverride => Str

The body of the message. If specified, this value overrides the default
message body.


=head2 Context => L<Paws::Pinpoint::MapOf__string>

A map of custom attributes to attach to the message for the address.
Attribute names are case sensitive.

For a push notification, this payload is added to the data.pinpoint
object. For an email or text message, this payload is added to
email/SMS delivery receipt event attributes.


=head2 RawContent => Str

The raw, JSON-formatted string to use as the payload for the message.
If specified, this value overrides all other values for the message.


=head2 Substitutions => L<Paws::Pinpoint::MapOfListOf__string>

A map of the message variables to merge with the variables specified
for the default message (DefaultMessage.Substitutions). The variables
specified in this map take precedence over all other variables.


=head2 TitleOverride => Str

The title or subject line of the message. If specified, this value
overrides the default message title or subject line.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Pinpoint>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

