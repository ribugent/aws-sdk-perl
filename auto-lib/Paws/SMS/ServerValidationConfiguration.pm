# Generated by default/object.tt
package Paws::SMS::ServerValidationConfiguration;
  use Moose;
  has Name => (is => 'ro', isa => 'Str', request_name => 'name', traits => ['NameInRequest']);
  has Server => (is => 'ro', isa => 'Paws::SMS::Server', request_name => 'server', traits => ['NameInRequest']);
  has ServerValidationStrategy => (is => 'ro', isa => 'Str', request_name => 'serverValidationStrategy', traits => ['NameInRequest']);
  has UserDataValidationParameters => (is => 'ro', isa => 'Paws::SMS::UserDataValidationParameters', request_name => 'userDataValidationParameters', traits => ['NameInRequest']);
  has ValidationId => (is => 'ro', isa => 'Str', request_name => 'validationId', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::SMS::ServerValidationConfiguration

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::SMS::ServerValidationConfiguration object:

  $service_obj->Method(Att1 => { Name => $value, ..., ValidationId => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::SMS::ServerValidationConfiguration object:

  $result = $service_obj->Method(...);
  $result->Att1->Name

=head1 DESCRIPTION

Configuration for validating an instance.

=head1 ATTRIBUTES


=head2 Name => Str

The name of the configuration.


=head2 Server => L<Paws::SMS::Server>




=head2 ServerValidationStrategy => Str

The validation strategy.


=head2 UserDataValidationParameters => L<Paws::SMS::UserDataValidationParameters>

The validation parameters.


=head2 ValidationId => Str

The ID of the validation.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::SMS>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

