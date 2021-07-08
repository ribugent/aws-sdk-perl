# Generated by default/object.tt
package Paws::LexModelsV2::SlotValueElicitationSetting;
  use Moose;
  has DefaultValueSpecification => (is => 'ro', isa => 'Paws::LexModelsV2::SlotDefaultValueSpecification', request_name => 'defaultValueSpecification', traits => ['NameInRequest']);
  has PromptSpecification => (is => 'ro', isa => 'Paws::LexModelsV2::PromptSpecification', request_name => 'promptSpecification', traits => ['NameInRequest']);
  has SampleUtterances => (is => 'ro', isa => 'ArrayRef[Paws::LexModelsV2::SampleUtterance]', request_name => 'sampleUtterances', traits => ['NameInRequest']);
  has SlotConstraint => (is => 'ro', isa => 'Str', request_name => 'slotConstraint', traits => ['NameInRequest'], required => 1);
  has WaitAndContinueSpecification => (is => 'ro', isa => 'Paws::LexModelsV2::WaitAndContinueSpecification', request_name => 'waitAndContinueSpecification', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::LexModelsV2::SlotValueElicitationSetting

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::LexModelsV2::SlotValueElicitationSetting object:

  $service_obj->Method(Att1 => { DefaultValueSpecification => $value, ..., WaitAndContinueSpecification => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::LexModelsV2::SlotValueElicitationSetting object:

  $result = $service_obj->Method(...);
  $result->Att1->DefaultValueSpecification

=head1 DESCRIPTION

Settings that you can use for eliciting a slot value.

=head1 ATTRIBUTES


=head2 DefaultValueSpecification => L<Paws::LexModelsV2::SlotDefaultValueSpecification>

A list of default values for a slot. Default values are used when
Amazon Lex hasn't determined a value for a slot. You can specify
default values from context variables, sesion attributes, and defined
values.


=head2 PromptSpecification => L<Paws::LexModelsV2::PromptSpecification>

The prompt that Amazon Lex uses to elicit the slot value from the user.


=head2 SampleUtterances => ArrayRef[L<Paws::LexModelsV2::SampleUtterance>]

If you know a specific pattern that users might respond to an Amazon
Lex request for a slot value, you can provide those utterances to
improve accuracy. This is optional. In most cases, Amazon Lex is
capable of understanding user utterances.


=head2 B<REQUIRED> SlotConstraint => Str

Specifies whether the slot is required or optional.


=head2 WaitAndContinueSpecification => L<Paws::LexModelsV2::WaitAndContinueSpecification>





=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::LexModelsV2>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

