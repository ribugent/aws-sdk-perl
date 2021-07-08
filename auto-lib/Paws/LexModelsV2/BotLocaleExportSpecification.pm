# Generated by default/object.tt
package Paws::LexModelsV2::BotLocaleExportSpecification;
  use Moose;
  has BotId => (is => 'ro', isa => 'Str', request_name => 'botId', traits => ['NameInRequest'], required => 1);
  has BotVersion => (is => 'ro', isa => 'Str', request_name => 'botVersion', traits => ['NameInRequest'], required => 1);
  has LocaleId => (is => 'ro', isa => 'Str', request_name => 'localeId', traits => ['NameInRequest'], required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::LexModelsV2::BotLocaleExportSpecification

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::LexModelsV2::BotLocaleExportSpecification object:

  $service_obj->Method(Att1 => { BotId => $value, ..., LocaleId => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::LexModelsV2::BotLocaleExportSpecification object:

  $result = $service_obj->Method(...);
  $result->Att1->BotId

=head1 DESCRIPTION

Provides the bot locale parameters required for exporting a bot locale.

=head1 ATTRIBUTES


=head2 B<REQUIRED> BotId => Str

The identifier of the bot to create the locale for.


=head2 B<REQUIRED> BotVersion => Str

The version of the bot to export.


=head2 B<REQUIRED> LocaleId => Str

The identifier of the language and locale to export. The string must
match one of the locales in the bot.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::LexModelsV2>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

