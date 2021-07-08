# Generated by default/object.tt
package Paws::LexRuntimeV2::SessionState;
  use Moose;
  has ActiveContexts => (is => 'ro', isa => 'ArrayRef[Paws::LexRuntimeV2::ActiveContext]', request_name => 'activeContexts', traits => ['NameInRequest']);
  has DialogAction => (is => 'ro', isa => 'Paws::LexRuntimeV2::DialogAction', request_name => 'dialogAction', traits => ['NameInRequest']);
  has Intent => (is => 'ro', isa => 'Paws::LexRuntimeV2::Intent', request_name => 'intent', traits => ['NameInRequest']);
  has OriginatingRequestId => (is => 'ro', isa => 'Str', request_name => 'originatingRequestId', traits => ['NameInRequest']);
  has SessionAttributes => (is => 'ro', isa => 'Paws::LexRuntimeV2::StringMap', request_name => 'sessionAttributes', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::LexRuntimeV2::SessionState

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::LexRuntimeV2::SessionState object:

  $service_obj->Method(Att1 => { ActiveContexts => $value, ..., SessionAttributes => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::LexRuntimeV2::SessionState object:

  $result = $service_obj->Method(...);
  $result->Att1->ActiveContexts

=head1 DESCRIPTION

The state of the user's session with Amazon Lex V2.

=head1 ATTRIBUTES


=head2 ActiveContexts => ArrayRef[L<Paws::LexRuntimeV2::ActiveContext>]

One or more contexts that indicate to Amazon Lex V2 the context of a
request. When a context is active, Amazon Lex V2 considers intents with
the matching context as a trigger as the next intent in a session.


=head2 DialogAction => L<Paws::LexRuntimeV2::DialogAction>

The next step that Amazon Lex V2 should take in the conversation with a
user.


=head2 Intent => L<Paws::LexRuntimeV2::Intent>

The active intent that Amazon Lex V2 is processing.


=head2 OriginatingRequestId => Str




=head2 SessionAttributes => L<Paws::LexRuntimeV2::StringMap>

Map of key/value pairs representing session-specific context
information. It contains application information passed between Amazon
Lex V2 and a client application.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::LexRuntimeV2>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

