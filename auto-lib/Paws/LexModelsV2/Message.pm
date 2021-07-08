# Generated by default/object.tt
package Paws::LexModelsV2::Message;
  use Moose;
  has CustomPayload => (is => 'ro', isa => 'Paws::LexModelsV2::CustomPayload', request_name => 'customPayload', traits => ['NameInRequest']);
  has ImageResponseCard => (is => 'ro', isa => 'Paws::LexModelsV2::ImageResponseCard', request_name => 'imageResponseCard', traits => ['NameInRequest']);
  has PlainTextMessage => (is => 'ro', isa => 'Paws::LexModelsV2::PlainTextMessage', request_name => 'plainTextMessage', traits => ['NameInRequest']);
  has SsmlMessage => (is => 'ro', isa => 'Paws::LexModelsV2::SSMLMessage', request_name => 'ssmlMessage', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::LexModelsV2::Message

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::LexModelsV2::Message object:

  $service_obj->Method(Att1 => { CustomPayload => $value, ..., SsmlMessage => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::LexModelsV2::Message object:

  $result = $service_obj->Method(...);
  $result->Att1->CustomPayload

=head1 DESCRIPTION

The object that provides message text and it's type.

=head1 ATTRIBUTES


=head2 CustomPayload => L<Paws::LexModelsV2::CustomPayload>

A message in a custom format defined by the client application.


=head2 ImageResponseCard => L<Paws::LexModelsV2::ImageResponseCard>

A message that defines a response card that the client application can
show to the user.


=head2 PlainTextMessage => L<Paws::LexModelsV2::PlainTextMessage>

A message in plain text format.


=head2 SsmlMessage => L<Paws::LexModelsV2::SSMLMessage>

A message in Speech Synthesis Markup Language (SSML).



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::LexModelsV2>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

