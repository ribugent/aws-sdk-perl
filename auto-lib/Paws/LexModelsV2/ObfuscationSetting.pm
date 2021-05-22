# Generated by default/object.tt
package Paws::LexModelsV2::ObfuscationSetting;
  use Moose;
  has ObfuscationSettingType => (is => 'ro', isa => 'Str', request_name => 'obfuscationSettingType', traits => ['NameInRequest'], required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::LexModelsV2::ObfuscationSetting

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::LexModelsV2::ObfuscationSetting object:

  $service_obj->Method(Att1 => { ObfuscationSettingType => $value, ..., ObfuscationSettingType => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::LexModelsV2::ObfuscationSetting object:

  $result = $service_obj->Method(...);
  $result->Att1->ObfuscationSettingType

=head1 DESCRIPTION

Determines whether Amazon Lex obscures slot values in conversation
logs.

=head1 ATTRIBUTES


=head2 B<REQUIRED> ObfuscationSettingType => Str

Value that determines whether Amazon Lex obscures slot values in
conversation logs. The default is to obscure the values.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::LexModelsV2>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

